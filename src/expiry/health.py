"""Self-monitoring: track failures of expiry's own work and alert when it is broken.

Components: "sync:<source>" (e.g. sync:entra, sync:ssl), "notify" (reminder delivery) and "backup".
Each run records success or failure. When a component keeps failing, an alert goes to
alerts.emails (default: notify.emails) through every channel, repeats every alerts.repeat_hours
while the problem lasts, and a "resolved" message follows once it works again.

Syncs run several times a day, so they alert after alerts.sync_failures failures in a row
(default 3). Notification and backup failures alert on the first failure.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timedelta, timezone

from expiry import __version__
from expiry.config import Config
from expiry.db import Store
from expiry.util import split_emails, utcnow_iso

log = logging.getLogger(__name__)

LABELS = {
    "sync:entra": "Entra ID sync",
    "sync:ssl": "SSL certificate sync",
    "notify": "Reminder delivery (email / webhooks)",
    "backup": "Database backup",
    "scan": "Certificate scan",
}
HINTS = {
    "sync:entra": "Check the app registration: client secret or certificate expired or removed, admin "
                  "consent revoked, or no network access to login.microsoftonline.com / graph.microsoft.com. "
                  "Run: expiry config check --connect",
    "sync:ssl": "Check network access from the server. Run: expiry sync --source ssl",
    "notify": "Reminders are NOT being delivered. Check the email settings (SMTP password, Graph Mail.Send "
              "permission, sender mailbox). Run: expiry test-notify, expiry history",
    "backup": "Check that the backup directory exists, is writable by the container (uid 10001) and has "
              "free space. Run: expiry backup create",
    "scan": "Check sources.ssl.scan (domains, networks) and DNS/network access from the server. "
            "Run: expiry ssl scan",
}


def _key(component: str) -> str:
    return f"health:{component}"


def label(component: str) -> str:
    return LABELS.get(component, component)


def record(store: Store, component: str, ok: bool, error: str = "") -> dict:
    """Record the outcome of one run of a component and return its new state."""
    state = store.kv_get(_key(component), {}) or {}
    now = utcnow_iso()
    if ok:
        if state.get("failures") and state.get("alerted_at"):
            state["recovered_pending"] = True
        state.update(failures=0, since=None, last_ok=now)
    else:
        state["failures"] = int(state.get("failures") or 0) + 1
        if state["failures"] == 1:
            state["since"] = now
        state.update(last_failure=now, last_error=(error or "unknown error")[:1000])
    store.kv_set(_key(component), state)
    return state


def states(store: Store) -> dict[str, dict]:
    rows = store.conn.execute("SELECT key FROM kv WHERE key LIKE 'health:%' ORDER BY key").fetchall()
    return {r["key"][len("health:"):]: store.kv_get(r["key"], {}) for r in rows}


def _enabled(cfg: Config, component: str) -> bool:
    """A component that was switched off (source or backups disabled) can't recover by itself."""
    if component.startswith("sync:"):
        return bool(cfg.get(f"sources.{component[5:]}.enabled"))
    if component == "backup":
        return bool(cfg.get("backup.enabled"))
    if component == "scan":
        return bool(cfg.get("sources.ssl.enabled") and cfg.get("sources.ssl.scan.enabled"))
    return True


def forget_disabled(cfg: Config, store: Store) -> None:
    for component in states(store):
        if not _enabled(cfg, component):
            store.kv_delete(_key(component))


def problems(store: Store, cfg: Config | None = None) -> dict[str, dict]:
    """Components whose most recent run failed (ignoring disabled ones when cfg is given)."""
    return {c: s for c, s in states(store).items()
            if s.get("failures") and (cfg is None or _enabled(cfg, c))}


def _threshold(cfg: Config, component: str) -> int:
    if component.startswith("sync:"):
        return max(1, int(cfg.get("alerts.sync_failures") or 3))
    return 1


def _server_name(cfg: Config) -> str:
    return cfg.get("alerts.server_name") or socket.gethostname()


def evaluate(cfg: Config, store: Store, email_sender=None, webhook_sender=None) -> list[str]:
    """Send any alert / resolved messages that are due. Returns a description of what was sent."""
    forget_disabled(cfg, store)
    if not cfg.get("alerts.enabled", True):
        return []
    repeat = timedelta(hours=float(cfg.get("alerts.repeat_hours") or 24))
    now = datetime.now(timezone.utc)
    sent = []
    for component, state in states(store).items():
        message = None
        if state.get("recovered_pending"):
            message = ("resolved", component, state)
        elif state.get("failures", 0) >= _threshold(cfg, component):
            last = state.get("alerted_at")
            if not last or now - datetime.fromisoformat(last) >= repeat:
                message = ("failing", component, state)
        if message is None:
            continue
        delivered = _deliver(cfg, *message, email_sender=email_sender, webhook_sender=webhook_sender)
        if not delivered:
            continue  # nothing got through: try again at the next evaluation
        if message[0] == "resolved":
            state.update(recovered_pending=False, alerted_at=None)
        else:
            state["alerted_at"] = utcnow_iso()
        store.kv_set(_key(component), state)
        sent.append(f"{message[0]}: {component} via {', '.join(delivered)}")
    return sent


def _deliver(cfg: Config, kind: str, component: str, state: dict, email_sender=None, webhook_sender=None) -> list[str]:
    from expiry.notify import send_message

    name = label(component)
    server = _server_name(cfg)
    if kind == "resolved":
        subject = f"[Expiry] RESOLVED: {name} is working again ({server})"
        lines = [f"{name} on {server} is working again.", f"Last success: {state.get('last_ok')}"]
    else:
        subject = f"[Expiry] ALERT: {name} is failing ({server})"
        lines = [
            f"{name} on {server} is failing.",
            f"Failing since: {state.get('since')} ({state.get('failures')} failed run(s) in a row)",
            f"Last error: {state.get('last_error')}",
            f"What to check: {HINTS.get(component, 'Run: expiry status')}",
        ]
    lines.append(f"-- expiry {__version__} self-monitoring (alerts.* in config.yaml)")

    recipients = split_emails(cfg.get("alerts.emails") or cfg.get("notify.emails") or [])
    delivered = send_message(cfg, recipients, subject, lines, email_sender, webhook_sender)
    if delivered:
        log.warning("%s alert sent for %s via %s", kind, component, ", ".join(delivered))
    return delivered
