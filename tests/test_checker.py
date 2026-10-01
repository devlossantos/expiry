from datetime import timedelta

import pytest
from conftest import TODAY, make_config

from expiry.checker import due_stage, run_check
from expiry.notify import Renderer, item_context


@pytest.mark.parametrize("days_left,expected", [
    (45, None), (31, None), (30, 30), (20, 30), (14, 14), (10, 14), (2, 14), (1, 1),
    (0, 0), (-3, 0), (-7, 0), (-8, None),
])
def test_due_stage(days_left, expected):
    assert due_stage(days_left, [30, 14, 1], True) == expected


def test_due_stage_without_expiry_day():
    assert due_stage(0, [30, 14, 1], False) == 1
    assert due_stage(-1, [30, 14, 1], False) is None


class FakeSender:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, to, msg):
        if self.fail:
            raise ConnectionError("smtp down")
        self.sent.append((to, msg))


def test_each_stage_sent_once_and_progresses(store, cfg):
    r = store.add("Cert A", TODAY + timedelta(days=30), "t")
    sender = FakeSender()

    res = run_check(cfg, store, TODAY, email_sender=sender)
    assert res.sent == 1 and len(sender.sent) == 1
    assert sender.sent[0][0] == ["ops@example.com"]
    assert "Cert A" in sender.sent[0][1].subject

    # same day again: nothing new
    assert run_check(cfg, store, TODAY, email_sender=sender).due == []
    # 10 days later -> still within the 30-day stage window, already sent
    assert run_check(cfg, store, TODAY + timedelta(days=10), email_sender=sender).due == []
    # 16 days later -> 14-day stage
    res = run_check(cfg, store, TODAY + timedelta(days=16), email_sender=sender)
    assert [d.stage for d in res.due] == [14]
    # day before
    res = run_check(cfg, store, TODAY + timedelta(days=29), email_sender=sender)
    assert [d.stage for d in res.due] == [1]
    # expiry day
    res = run_check(cfg, store, TODAY + timedelta(days=30), email_sender=sender)
    assert [d.stage for d in res.due] == [0]
    assert len(sender.sent) == 4
    assert store.sent_stages(r.id, r.expires_on) == {30, 14, 1, 0}


def test_late_addition_gets_single_tightest_notification(store, cfg):
    store.add("Late", TODAY + timedelta(days=5), "t")
    sender = FakeSender()
    res = run_check(cfg, store, TODAY, email_sender=sender)
    assert [d.stage for d in res.due] == [14]
    # later the 30-day stage is never sent retroactively
    assert run_check(cfg, store, TODAY + timedelta(days=1), email_sender=sender).due == []


def test_renewal_resets_cycle(store, cfg):
    r = store.add("Renew me", TODAY + timedelta(days=1), "t")
    sender = FakeSender()
    run_check(cfg, store, TODAY, email_sender=sender)
    store.update(r.id, "t", expires_on=TODAY + timedelta(days=30))
    res = run_check(cfg, store, TODAY, email_sender=sender)
    assert [d.stage for d in res.due] == [30]


def test_failure_is_recorded_and_retried(store, cfg):
    store.add("Flaky", TODAY + timedelta(days=14), "t")
    res = run_check(cfg, store, TODAY, email_sender=FakeSender(fail=True))
    assert res.failed == 1 and res.sent == 0
    assert store.history()[0]["status"] == "failed"
    res = run_check(cfg, store, TODAY, email_sender=FakeSender())
    assert res.sent == 1


def test_muted_and_inactive_are_skipped(store, cfg):
    r1 = store.add("Muted", TODAY + timedelta(days=1), "t")
    store.update(r1.id, "t", muted=True)
    r2 = store.add("Gone", TODAY + timedelta(days=1), "t", source="ssl", external_id="ssl:x:443")
    store.remove(r2.id, "t")  # synced -> ignored
    assert run_check(cfg, store, TODAY, email_sender=FakeSender()).due == []


def test_per_reminder_recipients_and_digest(store):
    cfg = make_config(notify__emails=["ops@example.com"], notify__mode="digest")
    store.add("A", TODAY + timedelta(days=1), "t")
    store.add("B", TODAY + timedelta(days=14), "t", notify=["dev@example.com"])
    sender = FakeSender()
    run_check(cfg, store, TODAY, email_sender=sender)
    by_to = {tuple(to): msg for to, msg in sender.sent}
    assert set(by_to) == {("ops@example.com",), ("dev@example.com",)}
    assert "2 items" in by_to[("ops@example.com",)].subject
    assert "B" in by_to[("dev@example.com",)].subject


def test_webhooks_count_as_delivery(store):
    cfg = make_config(email__enabled=False, notify__webhooks=[{"url": "https://hook", "format": "slack"}])
    store.add("Hooked", TODAY + timedelta(days=1), "t")
    calls = []
    res = run_check(cfg, store, TODAY, webhook_sender=lambda hook, items: calls.append(items))
    assert res.sent == 1 and len(calls) == 1 and calls[0][0]["name"] == "Hooked"


def test_default_template_renders(store, cfg):
    r = store.add("Tmpl <b>", TODAY - timedelta(days=2), "t", notes="n & m")
    out = Renderer(cfg).render([item_context(r, TODAY, 0, cfg.date_format)], TODAY)
    assert out.subject == "[Expiry] Tmpl <b> has EXPIRED"
    assert "Tmpl &lt;b&gt;" in out.html  # autoescaped
    assert "expired 2 days ago" in out.text
    assert "Expires: 28/09/2026" in out.text  # Irish date format by default
    assert "Monday, 28 September 2026" in out.html
    assert "30/09/2026" in out.html  # "sent on" date


HOOK = {"url": "https://hook.example/secret-token", "format": "teams"}


def test_email_failure_is_retried_even_when_a_webhook_worked(store):
    """The bug this replaced: one channel succeeding marked the reminder 'sent', so a broken SMTP
    password stopped every email for as long as a webhook worked, and no alert fired."""
    cfg = make_config(notify__emails=["ops@example.com"], email__smtp__host="localhost",
                      email__from="expiry@example.com", notify__webhooks=[HOOK])
    store.add("Payroll API secret", TODAY + timedelta(days=10), "t")
    hook_calls = []

    res = run_check(cfg, store, TODAY, email_sender=FakeSender(fail=True),
                    webhook_sender=lambda h, items: hook_calls.append(items))
    assert res.failed == 1 and res.sent == 0, "a partial delivery must count as a failure"
    assert store.history()[0]["status"] == "partial"
    assert len(hook_calls) == 1

    # next check: the email is retried, the webhook is NOT repeated
    sender = FakeSender()
    res = run_check(cfg, store, TODAY, email_sender=sender, webhook_sender=lambda h, items: hook_calls.append(items))
    assert res.sent == 1 and res.failed == 0
    assert [to for to, _ in sender.sent] == [["ops@example.com"]]
    assert len(hook_calls) == 1, "the webhook already had this stage"
    # and then it is complete
    assert run_check(cfg, store, TODAY, email_sender=FakeSender(), webhook_sender=lambda h, i: None).due == []


def test_partial_failure_raises_the_self_monitoring_alert_state(store):
    from expiry import health

    cfg = make_config(notify__emails=["ops@example.com"], email__smtp__host="localhost",
                      email__from="expiry@example.com", notify__webhooks=[HOOK])
    store.add("X", TODAY + timedelta(days=1), "t")
    run_check(cfg, store, TODAY, email_sender=FakeSender(fail=True), webhook_sender=lambda h, i: None)
    assert health.problems(store)["notify"]["failures"] == 1


def test_only_the_failed_recipient_is_retried(store):
    """Two recipients in separate digest emails: one fails, only that one is sent again."""
    cfg = make_config(notify__emails=["ops@example.com"], notify__mode="digest",
                      email__smtp__host="localhost", email__from="expiry@example.com")
    store.add("A", TODAY + timedelta(days=1), "t")
    store.add("B", TODAY + timedelta(days=1), "t", notify=["Dev@Example.com"])

    class FailFor(FakeSender):
        def send(self, to, msg):
            if "dev@example.com" in [a.lower() for a in to]:
                raise ConnectionError("mailbox full")
            self.sent.append((to, msg))

    first = FailFor()
    res = run_check(cfg, store, TODAY, email_sender=first)
    assert res.failed == 1  # B reached ops but not dev
    retry = FakeSender()
    res = run_check(cfg, store, TODAY, email_sender=retry)
    assert [sorted(a.lower() for a in to) for to, _ in retry.sent] == [["dev@example.com"]]
    assert res.sent == 1 and res.failed == 0


def test_webhook_url_is_never_stored(store):
    cfg = make_config(email__enabled=False, notify__webhooks=[HOOK])
    store.add("Hooked", TODAY + timedelta(days=1), "t")
    run_check(cfg, store, TODAY, webhook_sender=lambda h, i: None)
    row = store.conn.execute("SELECT * FROM notifications").fetchone()
    assert "secret-token" not in " ".join(str(v) for v in dict(row).values())


def test_a_version_1_database_is_migrated(tmp_path):
    import sqlite3

    from expiry.db import SCHEMA, Store

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    with Store(str(path)) as s:
        cols = {r["name"] for r in s.conn.execute("PRAGMA table_info(notifications)")}
        assert "keys" in cols
        assert s.conn.execute("PRAGMA user_version").fetchone()[0] >= 2
