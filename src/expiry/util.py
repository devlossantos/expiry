"""Small helpers shared across the app: dates, actors, host parsing."""

from __future__ import annotations

import calendar
import getpass
import ipaddress
import os
import re
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RELATIVE = re.compile(r"^\+(\d+)([dwmy])$")
_EMAIL = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


def today(tz: str) -> date:
    return datetime.now(ZoneInfo(tz)).date()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_months(d: date, months: int) -> date:
    month_index = d.month - 1 + months
    year = d.year + month_index // 12
    month = month_index % 12 + 1
    day = min(d.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


DEFAULT_DATE_FORMAT = "%d/%m/%Y"  # Irish / UK: 31/12/2026


def format_date(d: date, fmt: str = DEFAULT_DATE_FORMAT) -> str:
    return d.strftime(fmt or DEFAULT_DATE_FORMAT)


def parse_date(value: str, base: date, fmt: str | None = None) -> date:
    """Parse the configured date format (e.g. DD/MM/YYYY), YYYY-MM-DD, or a relative
    offset such as +90d, +2w, +6m, +1y."""
    v = value.strip().lower()
    m = _RELATIVE.match(v)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        if unit == "d":
            return base + timedelta(days=n)
        if unit == "w":
            return base + timedelta(weeks=n)
        if unit == "m":
            return add_months(base, n)
        return add_months(base, 12 * n)
    if _ISO_DATE.match(v):
        try:
            return date.fromisoformat(v)
        except ValueError:
            pass
    elif fmt:
        try:
            return datetime.strptime(value.strip(), fmt).date()
        except ValueError:
            pass
    example = f"{format_date(date(2026, 12, 31), fmt)}, " if fmt else ""
    raise ValueError(f"invalid date '{value}': use {example}2026-12-31 or a relative value like +90d, +6m, +1y")


def parse_graph_datetime(value: str) -> datetime:
    """Parse Microsoft Graph timestamps (7 fractional digits, trailing Z) into aware UTC datetimes."""
    v = value.strip().replace("Z", "+00:00")
    v = re.sub(r"(\.\d{6})\d+", r"\1", v)
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def describe_days(days: int) -> str:
    if days > 1:
        return f"in {days} days"
    if days == 1:
        return "tomorrow"
    if days == 0:
        return "today"
    if days == -1:
        return "expired yesterday"
    return f"expired {-days} days ago"


def actor() -> str:
    name = os.environ.get("EXPIRY_ACTOR", "").strip()
    if name:
        return name
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def is_email(value: str) -> bool:
    return bool(_EMAIL.match(value.strip()))


def split_emails(value: str | list | None) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        value = re.split(r"[,;\s]+", value)
    out: list[str] = []
    for v in value:
        v = str(v).strip()
        if v and v.lower() not in (x.lower() for x in out):
            out.append(v)
    return out


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_host_port(text: str, default_port: int = 443) -> tuple[str, int]:
    """Accept 'host', 'host:port', '[v6]:port', 'v6', or a full URL."""
    t = text.strip()
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t, flags=re.I)  # strip scheme
    t = t.split("/", 1)[0].split("?", 1)[0]
    t = t.rsplit("@", 1)[-1]  # strip user:pass@
    if not t:
        raise ValueError(f"invalid host '{text}'")
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
        return host, port
    if t.count(":") == 1:
        host, port_s = t.split(":")
        if not port_s.isdigit():
            raise ValueError(f"invalid port in '{text}'")
        return host.lower(), int(port_s)
    if t.count(":") > 1 and is_ip(t):  # bare IPv6
        return t, default_port
    return t.lower(), default_port
