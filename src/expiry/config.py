"""Configuration loading, ${ENV} expansion, validation and masking."""

from __future__ import annotations

import copy
import os
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from expiry.util import DEFAULT_DATE_FORMAT, is_email

SEARCH_PATHS = ["/config/config.yaml", "/etc/expiry/config.yaml", "./config.yaml"]

DEFAULT_SUBJECT = (
    "{% if certificate %}[Expiry] Certificate {{ certificate.name }} "
    "{% if item.expired %}has EXPIRED{% else %}expires {{ item.when }}{% endif %} ({{ items|length }} servers)"
    "{% elif items|length > 1 %}[Expiry] {{ items|length }} items are expiring soon"
    "{% elif item.expired %}[Expiry] {{ item.name }} has EXPIRED"
    "{% else %}[Expiry] {{ item.name }} expires {{ item.when }}{% endif %}"
)

DEFAULTS: dict[str, Any] = {
    "timezone": "",  # empty -> $TZ or UTC
    "date_format": DEFAULT_DATE_FORMAT,  # how dates are shown and typed: 31/12/2026
    "database": "/data/expiry.db",
    "schedule": {
        "sync": "0 */6 * * *",   # pull Entra / SSL expiry dates every 6 hours
        "check": "0 8 * * *",    # evaluate reminders and send notifications daily at 08:00
        "run_on_start": True,
    },
    "backup": {
        "enabled": True,
        "schedule": "30 2 * * *",      # daily at 02:30
        "directory": "",               # empty = /backups if a folder is mounted there, else /data/backups
        "keep": 14,                    # number of backups to keep
    },
    "alerts": {
        "enabled": True,          # email/webhook when expiry itself is failing
        "sync_failures": 3,       # alert after this many failed syncs in a row
        "repeat_hours": 24,       # repeat the alert while the problem lasts
        "emails": [],             # empty = notify.emails
        "server_name": "",        # shown in alerts; empty = container hostname
    },
    "notify": {
        "days_before": [30, 14, 1],
        "on_expiry_day": True,
        "mode": "individual",  # individual | digest
        "emails": [],
        "webhooks": [],
    },
    "email": {
        "enabled": True,
        "transport": "smtp",  # smtp | graph
        "from": "",
        "subject": DEFAULT_SUBJECT,
        "template_file": "",
        "smtp": {
            "host": "",
            "port": 587,
            "security": "starttls",  # starttls | ssl | none
            "username": "",
            "password": "",
            "timeout": 30,
        },
        "graph": {"sender": ""},
    },
    "entra": {
        "tenant_id": "",
        "client_id": "",
        "client_secret": "",
        "certificate_path": "",
        "certificate_thumbprint": "",
        "authority_host": "https://login.microsoftonline.com",
        "graph_url": "https://graph.microsoft.com",
    },
    "sources": {
        "entra": {
            "enabled": False,
            "include_secrets": True,
            "include_certificates": True,
            "include_service_principals": False,
            "include": [],
            "exclude": [],
            "notify_owners": False,
            "ignore_expired_after_days": 30,
        },
        "ssl": {
            "enabled": True,
            "timeout": 10,
            "hosts": [],
            "scan": {                      # find where certificates are installed, on a schedule
                "enabled": True,
                "schedule": "0 5 * * 1",   # weekly, Monday 05:00
                "discover_networks": True, # scan the private subnets this server can reach (no list needed)
                "discover_prefix": 24,     # size of each discovered network (a /16 LAN -> this server's /24)
                "exclude_networks": [],    # never scan these, e.g. ["10.9.0.0/16"]
                "match": "auto",           # auto | all | domains: which certificates to keep (auto = all
                                           # when no domain is set, else only those for your domains)
                "domains": [],             # e.g. [example.com]: also guess names under these domains
                "names": [],               # extra host names to try besides the built-in list
                "names_file": "",          # file with more names (one per line, or a DNS export)
                "networks": [],            # extra CIDR ranges to scan, e.g. ["10.1.2.0/24"]
                "ports": [443, 8443, 9443],
                "certificate_logs": True,  # also look up public names in crt.sh
                "timeout": 3,
                "add": True,               # track what is found automatically (false = only report)
            },
        },
    },
}

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_SECRET_KEYS = re.compile(r"(secret|password|token)", re.I)


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            v = os.environ.get(m.group(1))
            return v if v else (m.group(2) or "")
        return _ENV_REF.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: dict, path: Path | None):
        self.data = data
        self.path = path

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @property
    def timezone(self) -> str:
        return self.data.get("timezone") or os.environ.get("TZ") or "UTC"

    @property
    def date_format(self) -> str:
        return self.data.get("date_format") or DEFAULT_DATE_FORMAT

    @property
    def backup_dir(self) -> str:
        """backup.directory, or /backups when a host folder is mounted there, else /data/backups."""
        configured = self.data.get("backup", {}).get("directory")
        if configured:
            return configured
        return "/backups" if os.path.ismount("/backups") else "/data/backups"

    @property
    def db_path(self) -> str:
        return os.environ.get("EXPIRY_DB") or self.data.get("database") or "/data/expiry.db"


def find_config_path(explicit: str | None = None) -> Path | None:
    if explicit:
        return Path(explicit)
    env = os.environ.get("EXPIRY_CONFIG")
    if env:
        return Path(env)
    for p in SEARCH_PATHS:
        if Path(p).is_file():
            return Path(p)
    return None


def load_config(explicit: str | None = None) -> Config:
    path = find_config_path(explicit)
    raw: dict = {}
    if path is not None:
        if not path.is_file():
            if explicit:
                raise FileNotFoundError(f"config file not found: {path}")
            path = None
        else:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"{path}: top level must be a mapping")
            raw = loaded
    return Config(_expand(_merge(DEFAULTS, raw)), path)


def validate(cfg: Config) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    try:
        ZoneInfo(cfg.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        errors.append(f"timezone: unknown timezone '{cfg.timezone}' (use an IANA name such as Europe/Dublin)")

    probe = date(2026, 12, 31)
    fmt = cfg.date_format
    try:
        # a year is required (parsing without one is ambiguous and deprecated from Python 3.15)
        if not any(y in fmt for y in ("%Y", "%y")) or \
                datetime.strptime(probe.strftime(fmt), fmt).date() != probe:
            raise ValueError
    except ValueError:
        errors.append(f"date_format: '{fmt}' must contain day, month and year, e.g. %d/%m/%Y")

    from apscheduler.triggers.cron import CronTrigger

    from expiry.sources.sslcert import config_targets
    config_targets(cfg, errors)  # every sources.ssl.hosts entry must be a valid host[:port]

    if cfg.get("sources.ssl.scan.enabled"):
        if not (cfg.get("sources.ssl.scan.domains") or cfg.get("sources.ssl.scan.networks")
                or cfg.get("sources.ssl.scan.discover_networks", True)):
            errors.append("sources.ssl.scan: nothing to scan: set discover_networks: true, or list "
                          "domains / networks")
        if str(cfg.get("sources.ssl.scan.match") or "auto").lower() not in ("auto", "all", "domains"):
            errors.append("sources.ssl.scan.match: must be auto, all or domains")
        if str(cfg.get("sources.ssl.scan.match") or "").lower() == "domains" and \
                not cfg.get("sources.ssl.scan.domains"):
            errors.append("sources.ssl.scan.match: 'domains' needs sources.ssl.scan.domains")
        prefix = cfg.get("sources.ssl.scan.discover_prefix", 24)
        if not isinstance(prefix, int) or not 16 <= prefix <= 30:
            errors.append("sources.ssl.scan.discover_prefix: must be a number from 16 to 30 (24 = 256 addresses)")
        import ipaddress
        total = 0
        for net in cfg.get("sources.ssl.scan.networks") or []:
            try:
                total += ipaddress.ip_network(str(net), strict=False).num_addresses
            except ValueError:
                errors.append(f"sources.ssl.scan.networks: '{net}' is not a valid range (e.g. 10.1.2.0/24)")
        for net in cfg.get("sources.ssl.scan.exclude_networks") or []:
            try:
                ipaddress.ip_network(str(net), strict=False)
            except ValueError:
                errors.append(f"sources.ssl.scan.exclude_networks: '{net}' is not a valid range")
        nf = cfg.get("sources.ssl.scan.names_file")
        if nf and not Path(nf).is_file():
            errors.append(f"sources.ssl.scan.names_file: file not found: {nf}")
        ports = cfg.get("sources.ssl.scan.ports") or []
        if not all(isinstance(p, int) and 0 < p < 65536 for p in ports):
            errors.append("sources.ssl.scan.ports: must be a list of port numbers, e.g. [443, 8443]")
        elif total * max(len(ports), 1) > 65536:
            errors.append("sources.ssl.scan.networks: too many addresses x ports (max 65536); use smaller ranges")

    for key in ("schedule.sync", "schedule.check", "backup.schedule", "sources.ssl.scan.schedule"):
        expr = cfg.get(key)
        try:
            CronTrigger.from_crontab(str(expr))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{key}: invalid cron expression '{expr}' ({exc})")

    if cfg.get("backup.enabled"):
        keep = cfg.get("backup.keep")
        if not isinstance(keep, int) or keep < 1:
            errors.append("backup.keep: must be a whole number of at least 1")
    for key in ("alerts.sync_failures", "alerts.repeat_hours"):
        v = cfg.get(key)
        if not isinstance(v, (int, float)) or v < 1:
            errors.append(f"{key}: must be a number of at least 1")
    for e in cfg.get("alerts.emails") or []:
        if not is_email(str(e)):
            errors.append(f"alerts.emails: '{e}' is not a valid email address")

    days = cfg.get("notify.days_before")
    if not isinstance(days, list) or not all(isinstance(d, int) and d >= 0 for d in days):
        errors.append("notify.days_before: must be a list of non-negative integers, e.g. [30, 14, 1]")
    if cfg.get("notify.mode") not in ("individual", "digest"):
        errors.append("notify.mode: must be 'individual' or 'digest'")

    emails = cfg.get("notify.emails") or []
    for e in emails:
        if not is_email(str(e)):
            errors.append(f"notify.emails: '{e}' is not a valid email address")
    webhooks = cfg.get("notify.webhooks") or []
    for i, wh in enumerate(webhooks):
        if not isinstance(wh, dict) or not wh.get("url"):
            errors.append(f"notify.webhooks[{i}]: 'url' is required")
        elif wh.get("format", "generic") not in ("slack", "teams", "generic"):
            errors.append(f"notify.webhooks[{i}]: format must be slack, teams or generic")

    email_on = bool(cfg.get("email.enabled"))
    if email_on:
        transport = cfg.get("email.transport")
        if transport == "smtp":
            if not cfg.get("email.smtp.host"):
                errors.append("email.smtp.host: required when email.transport is smtp")
            if not cfg.get("email.from"):
                errors.append("email.from: required when email.transport is smtp")
            if cfg.get("email.smtp.security") not in ("starttls", "ssl", "none"):
                errors.append("email.smtp.security: must be starttls, ssl or none")
        elif transport == "graph":
            if not cfg.get("email.graph.sender"):
                errors.append("email.graph.sender: required when email.transport is graph")
            _check_entra_auth(cfg, errors, "email.transport=graph")
        else:
            errors.append("email.transport: must be 'smtp' or 'graph'")
        tf = cfg.get("email.template_file")
        if tf and not Path(tf).is_file():
            errors.append(f"email.template_file: file not found: {tf}")
        if not emails:
            warnings.append("notify.emails is empty: only per-reminder recipients (and owners) will be emailed")
    if not email_on and not webhooks:
        warnings.append("no notification channel enabled (email disabled and no webhooks)")

    if cfg.get("sources.entra.enabled"):
        _check_entra_auth(cfg, errors, "sources.entra.enabled")

    return errors, warnings


def _check_entra_auth(cfg: Config, errors: list[str], why: str) -> None:
    for key in ("tenant_id", "client_id"):
        if not cfg.get(f"entra.{key}"):
            errors.append(f"entra.{key}: required ({why})")
    has_secret = bool(cfg.get("entra.client_secret"))
    has_cert = bool(cfg.get("entra.certificate_path"))
    if not has_secret and not has_cert:
        errors.append(f"entra.client_secret or entra.certificate_path: required ({why})")
    if has_cert:
        from expiry.certauth import CertError, load_credential
        try:
            cred = load_credential(cfg.get("entra.certificate_path"), cfg.get("entra.certificate_thumbprint") or "")
            if cred.not_after is not None:
                from datetime import timezone
                if cred.not_after < datetime.now(timezone.utc):
                    errors.append(f"entra.certificate_path: certificate expired on {cred.not_after:%Y-%m-%d}")
        except CertError as exc:
            errors.append(f"entra.certificate_path: {exc}")


def masked(data: Any, key: str = "") -> Any:
    """Copy of the config with secrets hidden, for `expiry config show`."""
    if isinstance(data, dict):
        return {k: masked(v, k) for k, v in data.items()}
    if isinstance(data, list):
        return [masked(v, key) for v in data]
    if isinstance(data, str) and data:
        if _SECRET_KEYS.search(key):
            return "********"
        if key == "url":  # webhook URLs embed their credentials
            m = re.match(r"^(https?://[^/]+)", data)
            return (m.group(1) if m else "") + "/********"
    return data
