"""Decide which reminders are due and deliver the notifications.

Stages: each value in notify.days_before (default 30, 14, 1) is a stage, plus stage 0
("expires today / already expired") when notify.on_expiry_day is true.

A reminder is due for the tightest stage it has reached (e.g. 10 days left -> stage 14). Every
stage is sent at most once per expiry date; sending a tighter stage suppresses the looser ones, so a
reminder added with 5 days left gets exactly one email, not three. Renewing a reminder (new date)
starts the cycle again. Failed deliveries are retried on the next check.

Delivery is tracked per DESTINATION (each email address, each webhook), not per reminder. A stage
is complete only when every destination has it. If the email fails while a Teams webhook works,
the notification is recorded as "partial", the next check retries the email alone (the webhook is
not repeated), and the run counts as a failure for self-monitoring. Before this, any one channel
succeeding marked the reminder "sent": a broken SMTP password silently stopped every email for
as long as a webhook kept working, and no alert fired because nothing counted as failed.
"""

from __future__ import annotations

import hashlib
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
    # destinations that already have this stage (from an earlier, partly failed attempt)
    delivered: set[str] = field(default_factory=set)

    def pending_recipients(self) -> list[str]:
        return [a for a in self.recipients if email_key(a) not in self.delivered]


@dataclass
class CheckResult:
    due: list[DueItem] = field(default_factory=list)
    sent: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"due": len(self.due), "sent": self.sent, "failed": self.failed, "errors": self.errors}


def email_key(address: str) -> str:
    return f"email:{address.strip().lower()}"


def webhook_key(hook: dict) -> str:
    """Stable id for a webhook: its format plus a short hash of the URL (which embeds a secret, so
    the URL itself is never stored)."""
    digest = hashlib.sha256(str(hook.get("url", "")).encode()).hexdigest()[:10]
    return f"webhook:{hook.get('format', 'generic')}:{digest}"


def required_keys(cfg: Config, d: DueItem) -> set[str]:
    keys = {webhook_key(h) for h in (cfg.get("notify.webhooks") or [])}
    if cfg.get("email.enabled"):
        keys |= {email_key(a) for a in d.recipients}
    return keys


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
        due.append(DueItem(r, stage, recipients_for(cfg, r), store.delivered_keys(r.id, r.expires_on, stage)))
    return due


CHECK_LOCK_SECONDS = 15 * 60


def run_check(cfg: Config, store: Store, today: date, dry_run: bool = False,
              email_sender: EmailSender | None = None, webhook_sender=send_webhook) -> CheckResult:
    """Send what is due. Only one check runs at a time across processes: the daemon's 08:00 run and
    an `expiry check` typed at the same moment would otherwise both find the same items due and
    both send them, because a notification is recorded only after it has been delivered."""
    if dry_run:
        return CheckResult(due=find_due(cfg, store, today))
    import os

    if not store.acquire_lock("check", CHECK_LOCK_SECONDS, owner=f"pid {os.getpid()}"):
        result = CheckResult()
        result.errors.append("another check is running right now; nothing was sent by this one")
        return result
    try:
        return _run_check(cfg, store, today, email_sender, webhook_sender)
    finally:
        store.release_lock("check")


def _run_check(cfg: Config, store: Store, today: date, email_sender: EmailSender | None,
               webhook_sender) -> CheckResult:
    result = CheckResult(due=find_due(cfg, store, today))
    if not result.due:
        store.kv_set("last_check", {"at": utcnow_iso(), "result": result.summary()})
        return result

    email_on = bool(cfg.get("email.enabled"))
    webhooks = list(cfg.get("notify.webhooks") or [])
    renderer = Renderer(cfg)
    sender = email_sender or EmailSender(cfg)

    delivered_now: dict[int, set[str]] = {d.reminder.id: set() for d in result.due}
    errs: dict[int, list[str]] = {d.reminder.id: [] for d in result.due}

    if email_on:
        for recipients, batch in _email_batches(cfg, result.due):
            ctx = [item_context(d.reminder, today, d.stage, cfg.date_format) for d in batch]
            try:
                sender.send(recipients, renderer.render(ctx, today, certificate_group(batch)))
                sent_keys = {email_key(a) for a in recipients}
                for d in batch:
                    delivered_now[d.reminder.id] |= sent_keys & {email_key(a) for a in d.recipients}
                log.info("emailed %s about %s", ", ".join(recipients), ", ".join(d.reminder.name for d in batch))
            except Exception as exc:  # noqa: BLE001
                msg = f"email to {', '.join(recipients)} failed: {exc}"
                log.error(msg)
                result.errors.append(msg)
                for d in batch:
                    errs[d.reminder.id].append(msg)

    for hook in webhooks:
        key = webhook_key(hook)
        pending = [d for d in result.due if key not in d.delivered]
        if not pending:
            continue
        try:
            webhook_sender(hook, [item_context(d.reminder, today, d.stage, cfg.date_format) for d in pending])
            for d in pending:
                delivered_now[d.reminder.id].add(key)
        except Exception as exc:  # noqa: BLE001
            msg = f"webhook {hook.get('format', 'generic')} failed: {exc}"
            log.error(msg)
            result.errors.append(msg)
            for d in pending:
                errs[d.reminder.id].append(msg)

    if not email_on and not webhooks:
        result.errors.append("no notification channel configured (enable email or add a webhook)")

    unreachable = [d for d in result.due if not webhooks and not (email_on and d.recipients)]
    if unreachable and email_on:
        result.errors.append(f"{len(unreachable)} due item(s) have no recipient: set notify.emails "
                             f"(or --notify on the item): " + ", ".join(d.reminder.name for d in unreachable[:5]))

    unreachable_ids = {d.reminder.id for d in unreachable}
    for d in result.due:
        rid = d.reminder.id
        if rid in unreachable_ids:
            # nobody to send to: report it (status, alerts) but don't add a 'failed' row every check
            result.failed += 1
            continue
        now = delivered_now[rid]
        missing = required_keys(cfg, d) - d.delivered - now
        if not missing:
            status = "sent"
        elif now or d.delivered:
            status = "partial"   # some destinations have it; the next check retries only the rest
        else:
            status = "failed"
        channels = sorted({k.split(":", 1)[0] if k.startswith("email:") else k.rsplit(":", 1)[0] for k in now})
        store.record_notification(
            d.reminder, d.stage, status, channels,
            [k.split(":", 1)[1] for k in sorted(now) if k.startswith("email:")],
            "; ".join(errs[rid]) or ("no channel delivered" if status == "failed" else ""),
            keys=sorted(now),
        )
        if status == "sent":
            result.sent += 1
        else:
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
    """Recipient lists and the items each one gets. Only addresses that do not have the stage yet
    are included, so a retry after a partial failure never emails the same person twice."""
    with_recipients = [d for d in due if d.pending_recipients()]
    if cfg.get("notify.mode") != "digest":
        # one email per reminder, except servers sharing the same certificate (e.g. a wildcard on
        # several servers) at the same stage: one email listing all of them
        batches: dict[tuple, tuple[list[str], list[DueItem]]] = {}
        for d in with_recipients:
            sha = d.reminder.meta.get("sha256") if d.reminder.source == "ssl" else None
            pending = d.pending_recipients()
            key = ("cert", sha, d.stage, tuple(sorted(a.lower() for a in pending))) if sha \
                else ("item", d.reminder.id)
            batches.setdefault(key, (pending, []))[1].append(d)
        return list(batches.values())
    # digest: each recipient gets one email with every item relevant to them;
    # recipients who would receive the exact same list share one email.
    per_person: dict[str, list[DueItem]] = {}
    for d in with_recipients:
        for addr in d.pending_recipients():
            per_person.setdefault(addr.lower(), []).append(d)
    grouped: dict[tuple[int, ...], tuple[list[str], list[DueItem]]] = {}
    for addr, items in per_person.items():
        key = tuple(sorted(d.reminder.id for d in items))
        grouped.setdefault(key, ([], items))[0].append(addr)
    return list(grouped.values())
