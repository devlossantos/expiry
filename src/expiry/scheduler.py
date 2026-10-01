"""The long-running daemon (container default command): scheduled sync + check jobs."""

from __future__ import annotations

import logging
import signal
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from expiry import __version__, backup, health
from expiry.checker import run_check
from expiry.config import DEFAULTS, load_config, validate
from expiry.db import Store
from expiry.sources import run_sync
from expiry.util import today, utcnow_iso

log = logging.getLogger("expiry.daemon")

HEARTBEAT_SECONDS = 60


def _alerts(cfg, store: Store) -> None:
    """Send self-monitoring alerts that are due (expiry itself failing / recovered)."""
    try:
        for line in health.evaluate(cfg, store):
            log.warning("self-monitoring %s", line)
    except Exception:  # noqa: BLE001 - never let alerting break the job
        log.exception("self-monitoring evaluation failed")


def _job_sync(config_path: str | None) -> None:
    cfg = load_config(config_path)  # re-read so config edits apply without a restart
    with Store(cfg.db_path) as store:
        for r in run_sync(cfg, store):
            log.info("sync %s: found=%d created=%d updated=%d archived=%d errors=%d",
                     r.source, r.found, r.created, r.updated, r.archived, len(r.errors))
            for e in r.errors:
                log.warning("sync %s: %s", r.source, e)
        _alerts(cfg, store)


def _job_check(config_path: str | None) -> None:
    cfg = load_config(config_path)
    with Store(cfg.db_path) as store:
        try:
            res = run_check(cfg, store, today(cfg.timezone))
            log.info("check: due=%d sent=%d failed=%d", len(res.due), res.sent, res.failed)
        except Exception as exc:  # noqa: BLE001
            log.exception("check failed")
            health.record(store, "notify", False, str(exc))
        _alerts(cfg, store)
    _catch_up(config_path)


def _job_backup(config_path: str | None) -> None:
    cfg = load_config(config_path)
    with Store(cfg.db_path) as store:
        if not cfg.get("backup.enabled"):
            return
        try:
            path = backup.create_backup(cfg.db_path, cfg.backup_dir, keep=int(cfg.get("backup.keep")))
            store.kv_set("last_backup", {"at": utcnow_iso(), "file": str(path), "size": path.stat().st_size})
            health.record(store, "backup", True)
            log.info("backup written: %s", path)
        except Exception as exc:  # noqa: BLE001
            log.error("backup failed: %s", exc)
            health.record(store, "backup", False, str(exc))
        _alerts(cfg, store)


def _job_scan(config_path: str | None) -> None:
    from expiry.notify import send_message
    from expiry.sources import sslscan
    from expiry.util import split_emails

    cfg = load_config(config_path)
    with Store(cfg.db_path) as store:
        if not (cfg.get("sources.ssl.enabled") and cfg.get("sources.ssl.scan.enabled")):
            return
        store.kv_set("last_scan_attempt", utcnow_iso())
        try:
            result, added, new = sslscan.run_scheduled(cfg, store)
        except Exception as exc:  # noqa: BLE001
            log.exception("certificate scan failed")
            health.record(store, "scan", False, str(exc))
            _alerts(cfg, store)
            return
        health.record(store, "scan", True)
        store.audit("scan", "scan", None,
                     f"checked {result.names_checked} names, {result.addresses_checked} addresses: "
                     f"{len(result.found)} locations, {len(new)} new, {len(added)} added")
        store.kv_set("last_scan", {"at": utcnow_iso(), "found": len(result.found), "added": len(added),
                                   "untracked": len(new) - len(added), "warnings": result.warnings})
        log.info("scan: %d names, %d addresses checked; %d locations found, %d new, %d added",
                 result.names_checked, result.addresses_checked, len(result.found), len(new), len(added))
        for w in result.warnings:
            log.warning("scan: %s", w)
        if new:
            verb = "now tracked" if added else "not tracked yet (run: expiry ssl scan --add)"
            lines = [f"The weekly certificate scan found {len(new)} new location(s), {verb}:"]
            lines += [f"{f.location}: {f.info.common_name} ({f.info.issuer}), expires "
                      f"{f.info.not_after:%d/%m/%Y}{' [wildcard]' if sslscan.is_wildcard(f.info) else ''}"
                      for f in new]
            lines.append("-- expiry certificate scan (sources.ssl.scan in config.yaml)")
            send_message(cfg, split_emails(cfg.get("notify.emails") or []),
                         f"[Expiry] Certificate scan found {len(new)} new location(s)", lines)
        _alerts(cfg, store)


def _older_than(iso: str | None, hours: float) -> bool:
    if not iso:
        return True
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(iso) > timedelta(hours=hours)
    except ValueError:
        return True


def _job_startup(config_path: str | None) -> None:
    _job_sync(config_path)
    _job_check(config_path)  # includes the catch-up below


def _catch_up(config_path: str | None) -> None:
    """Run a daily backup / weekly scan that was missed because the machine was off or asleep
    (e.g. a PC that isn't on at 02:30). Called at start-up and after every check."""
    cfg = load_config(config_path)
    with Store(cfg.db_path) as store:
        last_backup = (store.kv_get("last_backup") or {}).get("at")
        # scans: the last *attempt*, so a failing scan isn't repeated every hour (it alerts instead)
        last_scan = store.kv_get("last_scan_attempt") or (store.kv_get("last_scan") or {}).get("at")
    if cfg.get("backup.enabled") and _older_than(last_backup, 24):
        log.info("catching up: last backup %s", last_backup or "never")
        _job_backup(config_path)
    if cfg.get("sources.ssl.enabled") and cfg.get("sources.ssl.scan.enabled") and _older_than(last_scan, 7 * 24):
        log.info("catching up: last certificate scan %s", last_scan or "never")
        _job_scan(config_path)


def cron_trigger(cfg, key: str, tz: ZoneInfo) -> CronTrigger:
    """The schedule at config key; an invalid expression falls back to the default instead of
    crashing the service (the error is logged and shown by `expiry config check`)."""
    expr = cfg.get(key)
    try:
        return CronTrigger.from_crontab(str(expr), timezone=tz)
    except ValueError as exc:
        node = DEFAULTS
        for part in key.split("."):
            node = node[part]
        log.error("%s: invalid cron expression '%s' (%s); using the default '%s'", key, expr, exc, node)
        return CronTrigger.from_crontab(node, timezone=tz)


def configure_logging(tz: ZoneInfo) -> logging.Formatter:
    """Log to stdout with timestamps in the configured timezone (the slim image may lack system
    zoneinfo for $TZ). The converter is set on the instance: a function stored on the Formatter
    class would be bound as a method and break every log call."""
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    formatter.converter = lambda ts: datetime.fromtimestamp(ts, tz).timetuple()
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    return formatter


def run_daemon(config_path: str | None = None) -> None:
    cfg = load_config(config_path)
    try:
        tz = ZoneInfo(cfg.timezone)
    except Exception:  # noqa: BLE001 - reported by validate() below
        tz = ZoneInfo("UTC")
    configure_logging(tz)
    errors, warnings = validate(cfg)
    log.info("expiry %s starting (config: %s, db: %s, tz: %s)", __version__, cfg.path or "defaults",
             cfg.db_path, cfg.timezone)
    for w in warnings:
        log.warning("config: %s", w)
    for e in errors:
        log.error("config: %s", e)

    sched = BlockingScheduler(timezone=tz, job_defaults={"coalesce": True, "max_instances": 1,
                                                         "misfire_grace_time": 3600})
    sched.add_job(_job_sync, cron_trigger(cfg, "schedule.sync", tz), args=[config_path], id="sync", name="sync")
    sched.add_job(_job_check, cron_trigger(cfg, "schedule.check", tz), args=[config_path], id="check", name="check")
    if cfg.get("backup.enabled"):
        sched.add_job(_job_backup, cron_trigger(cfg, "backup.schedule", tz),
                      args=[config_path], id="backup", name="backup")
    if cfg.get("sources.ssl.enabled") and cfg.get("sources.ssl.scan.enabled"):
        sched.add_job(_job_scan, cron_trigger(cfg, "sources.ssl.scan.schedule", tz),
                      args=[config_path], id="scan", name="scan")

    def heartbeat() -> None:
        with Store(cfg.db_path) as store:
            store.kv_set("daemon", {
                "heartbeat": utcnow_iso(),
                "started": started,
                "version": __version__,
                "next": {j.id: j.next_run_time.isoformat() if j.next_run_time else None
                         for j in sched.get_jobs() if j.id in ("sync", "check", "backup", "scan")},
            })

    started = utcnow_iso()
    sched.add_job(heartbeat, "interval", seconds=HEARTBEAT_SECONDS, id="heartbeat",
                  next_run_time=datetime.now(tz))
    if cfg.get("schedule.run_on_start", True):
        sched.add_job(_job_startup, args=[config_path], id="startup", next_run_time=datetime.now(tz))

    def stop(signum, _frame) -> None:
        log.info("received signal %s, shutting down", signum)
        sched.shutdown(wait=False)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info("schedule: sync '%s', check '%s', backup '%s' (%s)", cfg.get("schedule.sync"),
             cfg.get("schedule.check"), cfg.get("backup.schedule") if cfg.get("backup.enabled") else "off", tz)
    sched.start()
