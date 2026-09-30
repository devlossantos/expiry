"""Decide which reminders are due and deliver the notifications.

Stages: each value in notify.days_before (default 30, 14, 1) is a stage, plus stage 0
("expires today / already expired") when notify.on_expiry_day is true.

A reminder is due for the tightest stage it has reached (e.g. 10 days left -> stage 14). Every
stage is sent at most once per expiry date; sending a tighter stage suppresses the looser ones, so a
reminder added with 5 days left gets exactly one email, not three. Renewing a reminder (new date)
starts the cycle again. Failed deliveries are retried on the next check.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date

from expiry import health
from expiry.config import Config
from expiry.db import Reminder, Store
from expiry.notify import EmailSender, Renderer, item_context, send_webhook
from expiry.util import split_emails, utcnow_iso

log = logging.getLogger(__name__)

OVERDUE_WINDOW_DAYS = 7  # keep sending the "expired" stage (once) for items expired up to a week ago


def due_stage(days_left: int, days_before: list[int], on_expiry_day: bool) -> int | None:
    stages = sorted({d for d in days_before if d > 0} | ({0} if on_expiry_day else set()))
    if not stages:
        return None
    if days_left < 0:
        return 0 if on_expiry_day and days_left >= -OVERDUE_WINDOW_DAYS else None
    reached = [s for s in stages if s >= days_left]
    return min(reached) if reached else None


@dataclass
class DueItem:
    reminder: Reminder
    stage: int
    recipients: list[str]


@dataclass
class CheckResult:
    due: list[DueItem] = field(default_factory=list)
    sent: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"due": len(self.due), "sent": self.sent, "failed": self.failed, "errors": self.errors}


def recipients_for(cfg: Config, r: Reminder) -> list[str]:
    return split_emails(list(cfg.get("notify.emails") or []) + r.notify + list(r.meta.get("owners") or []))


def find_due(cfg: Config, store: Store, today: date) -> list[DueItem]:
    days_before = list(cfg.get("notify.days_before") or [])
    on_day = bool(cfg.get("notify.on_expiry_day", True))
    due = []
    for r in store.list(statuses=("active",)):
        if r.muted:
            continue
        stage = due_stage(r.days_left(today), days_before, on_day)
        if stage is None:
            continue
        if any(s <= stage for s in store.sent_stages(r.id, r.expires_on)):
            continue
        due.append(DueItem(r, stage, recipients_for(cfg, r)))
    return due


def run_check(cfg: Config, store: Store, today: date, dry_run: bool = False,
              email_sender: EmailSender | None = None, webhook_sender=send_webhook) -> CheckResult:
    result = CheckResult(due=find_due(cfg, store, today))
    if dry_run or not result.due:
        if not dry_run:
            store.kv_set("last_check", {"at": utcnow_iso(), "result": result.summary()})
        return result

    email_on = bool(cfg.get("email.enabled"))
    webhooks = list(cfg.get("notify.webhooks") or [])
    renderer = Renderer(cfg)
    sender = email_sender or EmailSender(cfg)

    ok: dict[int, list[str]] = {d.reminder.id: [] for d in result.due}       # reminder id -> channels delivered
    errs: dict[int, list[str]] = {d.reminder.id: [] for d in result.due}
    sent_to: dict[int, list[str]] = {d.reminder.id: [] for d in result.due}

    if email_on:
        for recipients, batch in _email_batches(cfg, result.due):
            ctx = [item_context(d.reminder, today, d.stage, cfg.date_format) for d in batch]
            try:
                sender.send(recipients, renderer.render(ctx, today, certificate_group(batch)))
                for d in batch:
                    ok[d.reminder.id].append("email")
                    sent_to[d.reminder.id].extend(recipients)
                log.info("emailed %s about %s", ", ".join(recipients), ", ".join(d.reminder.name for d in batch))
            except Exception as exc:  # noqa: BLE001
                msg = f"email to {', '.join(recipients)} failed: {exc}"
                log.error(msg)
                result.errors.append(msg)
                for d in batch:
                    errs[d.reminder.id].append(msg)

    if webhooks:
        ctx = [item_context(d.reminder, today, d.stage, cfg.date_format) for d in result.due]
        for hook in webhooks:
            try:
                webhook_sender(hook, ctx)
                for d in result.due:
                    ok[d.reminder.id].append(f"webhook:{hook.get('format', 'generic')}")
            except Exception as exc:  # noqa: BLE001
                msg = f"webhook {hook.get('format', 'generic')} failed: {exc}"
                log.error(msg)
                result.errors.append(msg)
                for d in result.due:
                    errs[d.reminder.id].append(msg)

    if not email_on and not webhooks:
        result.errors.append("no notification channel configured (enable email or add a webhook)")

    for d in result.due:
        rid = d.reminder.id
        if ok[rid]:
            store.record_notification(d.reminder, d.stage, "sent", ok[rid], split_emails(sent_to[rid]),
                                      "; ".join(errs[rid]))
            result.sent += 1
        else:
            store.record_notification(d.reminder, d.stage, "failed", [], d.recipients,
                                      "; ".join(errs[rid]) or "no channel delivered")
            result.failed += 1

    store.kv_set("last_check", {"at": utcnow_iso(), "result": result.summary()})
    health.record(store, "notify", result.failed == 0, "; ".join(result.errors))
    return result


def certificate_group(batch: list[DueItem]) -> dict | None:
    """If a batch is several servers sharing one certificate, describe that certificate."""
    shas = {d.reminder.meta.get("sha256") for d in batch}
    if len(batch) < 2 or len(shas) != 1 or None in shas or any(d.reminder.source != "ssl" for d in batch):
        return None
    meta = batch[0].reminder.meta
    names = [meta.get("common_name") or ""] + list(meta.get("san") or [])
    return {"name": meta.get("common_name") or batch[0].reminder.name, "issuer": meta.get("issuer", ""),
            "wildcard": any(n.startswith("*.") for n in names), "servers": [d.reminder.name for d in batch]}


def _email_batches(cfg: Config, due: list[DueItem]) -> list[tuple[list[str], list[DueItem]]]:
    with_recipients = [d for d in due if d.recipients]
    if cfg.get("notify.mode") != "digest":
        # one email per reminder, except servers sharing the same certificate (e.g. a wildcard on
        # several servers) at the same stage: one email listing all of them
        batches: dict[tuple, tuple[list[str], list[DueItem]]] = {}
        for d in with_recipients:
            sha = d.reminder.meta.get("sha256") if d.reminder.source == "ssl" else None
            key = ("cert", sha, d.stage, tuple(sorted(a.lower() for a in d.recipients))) if sha \
                else ("item", d.reminder.id)
            batches.setdefault(key, (d.recipients, []))[1].append(d)
        return list(batches.values())
    # digest: each recipient gets one email with every item relevant to them;
    # recipients who would receive the exact same list share one email.
    per_person: dict[str, list[DueItem]] = {}
    for d in with_recipients:
        for addr in d.recipients:
            per_person.setdefault(addr.lower(), []).append(d)
    grouped: dict[tuple[int, ...], tuple[list[str], list[DueItem]]] = {}
    for addr, items in per_person.items():
        key = tuple(sorted(d.reminder.id for d in items))
        grouped.setdefault(key, ([], items))[0].append(addr)
    return list(grouped.values())
