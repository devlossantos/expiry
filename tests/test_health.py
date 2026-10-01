from datetime import datetime, timedelta, timezone

from conftest import make_config

from expiry import health


class Sender:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, to, msg):
        if self.fail:
            raise ConnectionError("smtp down")
        self.sent.append((to, msg))


def cfg(**kw):
    settings = {"notify__emails": ["ops@example.com"], "alerts__server_name": "srv1",
                "sources__entra__enabled": True, **kw}
    return make_config(**settings)


def test_sync_alert_after_threshold_then_repeat_then_resolved(store):
    c, s = cfg(), Sender()
    for _ in range(2):
        health.record(store, "sync:entra", False, "AADSTS7000222: client secret expired")
    assert health.evaluate(c, store, email_sender=s) == []  # below 3 failures
    health.record(store, "sync:entra", False, "AADSTS7000222: client secret expired")
    assert health.evaluate(c, store, email_sender=s) == ["failing: sync:entra via email"]
    subject = s.sent[0][1].subject
    assert subject == "[Expiry] ALERT: Entra ID sync is failing (srv1)"
    assert "AADSTS7000222" in s.sent[0][1].text and "config check --connect" in s.sent[0][1].text

    health.record(store, "sync:entra", False, "still broken")
    assert health.evaluate(c, store, email_sender=s) == []  # not again within repeat_hours
    state = store.kv_get("health:sync:entra")
    state["alerted_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    store.kv_set("health:sync:entra", state)
    assert health.evaluate(c, store, email_sender=s) == ["failing: sync:entra via email"]  # daily repeat

    health.record(store, "sync:entra", True)
    assert health.evaluate(c, store, email_sender=s) == ["resolved: sync:entra via email"]
    assert s.sent[-1][1].subject.startswith("[Expiry] RESOLVED: Entra ID sync")
    assert health.evaluate(c, store, email_sender=s) == []
    assert health.problems(store) == {}


def test_notify_and_backup_alert_on_first_failure(store):
    s = Sender()
    health.record(store, "backup", False, "No space left on device")
    health.record(store, "notify", False, "535 authentication failed")
    sent = health.evaluate(cfg(), store, email_sender=s)
    assert sorted(sent) == ["failing: backup via email", "failing: notify via email"]


def test_undelivered_alert_is_retried_and_webhook_fallback(store):
    health.record(store, "notify", False, "smtp down")
    assert health.evaluate(cfg(), store, email_sender=Sender(fail=True)) == []
    assert store.kv_get("health:notify").get("alerted_at") is None  # will retry
    calls = []
    c = cfg(notify__webhooks=[{"url": "https://hook", "format": "teams"}])
    sent = health.evaluate(c, store, email_sender=Sender(fail=True),
                           webhook_sender=lambda hook, title, lines: calls.append(title))
    assert sent == ["failing: notify via webhook:teams"] and "ALERT" in calls[0]


def test_alert_recipients_override_and_disable(store):
    s = Sender()
    health.record(store, "backup", False, "x")
    health.evaluate(cfg(alerts__emails=["oncall@example.com"]), store, email_sender=s)
    assert s.sent[0][0] == ["oncall@example.com"]
    health.record(store, "notify", False, "x")
    assert health.evaluate(cfg(alerts__enabled=False), store, email_sender=s) == []


def test_sync_and_check_record_health(store, monkeypatch):
    import expiry.sources as sources
    from expiry.checker import run_check

    class Boom:
        name = "entra"

        def fetch(self):
            raise RuntimeError("graph down")

    monkeypatch.setattr(sources, "build_sources", lambda cfg, store, only=None: {"entra": Boom()})
    sources.run_sync(cfg(), store)
    assert health.problems(store)["sync:entra"]["last_error"] == "graph down"

    from conftest import TODAY
    store.add("Due", TODAY + timedelta(days=1), "t")
    run_check(cfg(), store, TODAY, email_sender=Sender(fail=True))
    assert "smtp down" in health.problems(store)["notify"]["last_error"]
    run_check(cfg(), store, TODAY, email_sender=Sender())  # delivery works again
    assert "notify" not in health.problems(store)


def test_disabled_feature_stops_alerting(store):
    s = Sender()
    for _ in range(3):
        health.record(store, "sync:entra", False, "bad secret")
    health.record(store, "backup", False, "disk full")
    on = cfg(sources__entra__enabled=True)
    assert set(health.problems(store, on)) == {"sync:entra", "backup"}
    off = cfg(sources__entra__enabled=False, backup__enabled=False)
    assert health.problems(store, off) == {}
    assert health.evaluate(off, store, email_sender=s) == [] and s.sent == []
    assert health.states(store) == {}  # forgotten, so no daily repeats and no stale "failing"
