"""SQLite storage: reminders, SSL targets, notification history, audit log, key/value state."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from expiry.util import split_emails, utcnow_iso

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS reminders (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    expires_on   TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT 'manual',
    external_id  TEXT UNIQUE,
    notify       TEXT NOT NULL DEFAULT '',
    muted        INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'active',
    meta         TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    last_seen_at TEXT,
    created_by   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reminders_status ON reminders(status, expires_on);

CREATE TABLE IF NOT EXISTS notifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    reminder_id   INTEGER REFERENCES reminders(id) ON DELETE SET NULL,
    reminder_name TEXT NOT NULL,
    expires_on    TEXT NOT NULL,
    stage         INTEGER NOT NULL,
    status        TEXT NOT NULL,
    channels      TEXT NOT NULL DEFAULT '',
    recipients    TEXT NOT NULL DEFAULT '',
    error         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_reminder ON notifications(reminder_id, expires_on);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    reminder_id INTEGER,
    details     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ssl_targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL DEFAULT 443,
    sni        TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    UNIQUE(host, port, sni)
);

CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# Schema changes after version 1, keyed by the version they produce.
MIGRATIONS: dict[int, list[str]] = {
    # 2: which destinations (email:<address>, webhook:<format>:<hash>) each notification reached, so a
    #    partly failed delivery retries only what failed
    2: ["ALTER TABLE notifications ADD COLUMN keys TEXT NOT NULL DEFAULT ''"],
}


@dataclass
class Reminder:
    id: int
    name: str
    expires_on: date
    notes: str = ""
    source: str = "manual"
    external_id: str | None = None
    notify: list[str] = field(default_factory=list)
    muted: bool = False
    status: str = "active"
    meta: dict = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    last_seen_at: str | None = None
    created_by: str = ""

    def days_left(self, today: date) -> int:
        return (self.expires_on - today).days

    def to_dict(self, today: date | None = None) -> dict[str, Any]:
        d = {
            "id": self.id,
            "name": self.name,
            "expires_on": self.expires_on.isoformat(),
            "notes": self.notes,
            "source": self.source,
            "external_id": self.external_id,
            "notify": self.notify,
            "muted": self.muted,
            "status": self.status,
            "meta": self.meta,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
        }
        if today is not None:
            d["days_left"] = self.days_left(today)
        return d


@dataclass
class SslTarget:
    id: int
    host: str
    port: int
    sni: str = ""
    name: str = ""
    notes: str = ""
    created_at: str = ""
    created_by: str = ""


def _row_to_reminder(row: sqlite3.Row) -> Reminder:
    return Reminder(
        id=row["id"],
        name=row["name"],
        expires_on=date.fromisoformat(row["expires_on"]),
        notes=row["notes"],
        source=row["source"],
        external_id=row["external_id"],
        notify=split_emails(row["notify"]),
        muted=bool(row["muted"]),
        status=row["status"],
        meta=json.loads(row["meta"] or "{}"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_seen_at=row["last_seen_at"],
        created_by=row["created_by"],
    )


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 30000")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _migrate(self) -> None:
        """Bring the database up to SCHEMA_VERSION, one numbered step at a time.

        A fresh database gets SCHEMA (version 1) and then every step after it, so new and upgraded
        databases end up identical. To change the schema: append a step to MIGRATIONS and bump
        SCHEMA_VERSION. Never edit a step that has shipped; existing databases have already run it.
        """
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version < 1:
            with self.conn:
                self.conn.executescript(SCHEMA)
                self.conn.execute("PRAGMA user_version = 1")
            version = 1
        for target in range(version + 1, SCHEMA_VERSION + 1):
            with self.conn:
                for statement in MIGRATIONS[target]:
                    self.conn.execute(statement)
                self.conn.execute(f"PRAGMA user_version = {target}")

    # ------------------------------------------------------------------ reminders

    def add(
        self,
        name: str,
        expires_on: date,
        actor: str,
        notes: str = "",
        notify: Iterable[str] = (),
        source: str = "manual",
        external_id: str | None = None,
        meta: dict | None = None,
    ) -> Reminder:
        now = utcnow_iso()
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO reminders (name, expires_on, notes, source, external_id, notify, meta,
                                          created_at, updated_at, last_seen_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    name,
                    expires_on.isoformat(),
                    notes or "",
                    source,
                    external_id,
                    ",".join(notify),
                    json.dumps(meta or {}, sort_keys=True),
                    now,
                    now,
                    now if external_id else None,
                    actor,
                ),
            )
            rid = cur.lastrowid
            self._audit(actor, "add", rid, f"{name} expires {expires_on.isoformat()}")
        return self.get(rid)  # type: ignore[return-value]

    def get(self, rid: int) -> Reminder | None:
        row = self.conn.execute("SELECT * FROM reminders WHERE id = ?", (rid,)).fetchone()
        return _row_to_reminder(row) if row else None

    def get_by_external_id(self, external_id: str) -> Reminder | None:
        row = self.conn.execute("SELECT * FROM reminders WHERE external_id = ?", (external_id,)).fetchone()
        return _row_to_reminder(row) if row else None

    def list(
        self,
        statuses: Iterable[str] | None = ("active",),
        source: str | None = None,
        search: str | None = None,
    ) -> list[Reminder]:
        sql = "SELECT * FROM reminders WHERE 1=1"
        args: list[Any] = []
        if statuses is not None:
            statuses = list(statuses)
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args += statuses
        if source:
            sql += " AND source = ?"
            args.append(source)
        if search:
            sql += " AND (name LIKE ? OR notes LIKE ?)"
            args += [f"%{search}%", f"%{search}%"]
        sql += " ORDER BY expires_on, id"
        return [_row_to_reminder(r) for r in self.conn.execute(sql, args)]

    def update(self, rid: int, actor: str, **fields: Any) -> Reminder:
        allowed = {"name", "expires_on", "notes", "notify", "muted", "status", "meta"}
        current = self.get(rid)
        if current is None:
            raise KeyError(rid)
        sets, args, changes = [], [], []
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"cannot update field {key}")
            old = getattr(current, key)
            if key == "expires_on":
                value_db = value.isoformat()
            elif key == "notify":
                value = split_emails(value)
                value_db = ",".join(value)
            elif key == "muted":
                value = bool(value)
                value_db = int(value)
            elif key == "meta":
                value_db = json.dumps(value, sort_keys=True)
            else:
                value_db = value
            if old == value:
                continue
            sets.append(f"{key} = ?")
            args.append(value_db)
            if key != "meta":
                changes.append(f"{key}: {_fmt(old)} -> {_fmt(value)}")
        if not sets:
            return current
        sets.append("updated_at = ?")
        args += [utcnow_iso(), rid]
        with self.conn:
            self.conn.execute(f"UPDATE reminders SET {', '.join(sets)} WHERE id = ?", args)
            if changes:
                self._audit(actor, "edit", rid, "; ".join(changes))
        return self.get(rid)  # type: ignore[return-value]

    def remove(self, rid: int, actor: str) -> str:
        """Hard-delete manual reminders; mark synced ones 'ignored' so a sync won't re-create them."""
        r = self.get(rid)
        if r is None:
            raise KeyError(rid)
        with self.conn:
            if r.source == "manual":
                self.conn.execute("DELETE FROM reminders WHERE id = ?", (rid,))
                self._audit(actor, "remove", rid, r.name)
                return "deleted"
            self.conn.execute(
                "UPDATE reminders SET status = 'ignored', updated_at = ? WHERE id = ?", (utcnow_iso(), rid)
            )
            self._audit(actor, "ignore", rid, r.name)
            return "ignored"

    def restore(self, rid: int, actor: str) -> Reminder:
        r = self.get(rid)
        if r is None:
            raise KeyError(rid)
        with self.conn:
            self.conn.execute(
                "UPDATE reminders SET status = 'active', updated_at = ? WHERE id = ?", (utcnow_iso(), rid)
            )
            self._audit(actor, "restore", rid, r.name)
        return self.get(rid)  # type: ignore[return-value]

    # ------------------------------------------------------------------ sync helpers

    def upsert_external(
        self, source: str, external_id: str, name: str, expires_on: date, meta: dict, actor: str, notes: str = ""
    ) -> str:
        """Create or refresh a synced reminder. Returns created|updated|unchanged|ignored."""
        row = self.conn.execute("SELECT * FROM reminders WHERE external_id = ?", (external_id,)).fetchone()
        now = utcnow_iso()
        if row is None:
            self.add(name, expires_on, actor, notes=notes, source=source, external_id=external_id, meta=meta)
            return "created"
        current = _row_to_reminder(row)
        if current.status == "ignored":
            with self.conn:
                self.conn.execute("UPDATE reminders SET last_seen_at = ? WHERE id = ?", (now, current.id))
            return "ignored"
        changes = []
        if current.name != name:
            changes.append(f"name: {current.name} -> {name}")
        if current.expires_on != expires_on:
            changes.append(f"expires_on: {current.expires_on} -> {expires_on}")
        if current.status != "active":
            changes.append(f"status: {current.status} -> active")
        meta_json = json.dumps(meta, sort_keys=True)
        with self.conn:
            self.conn.execute(
                """UPDATE reminders SET name = ?, expires_on = ?, status = 'active', meta = ?, last_seen_at = ?,
                          updated_at = CASE WHEN ? THEN ? ELSE updated_at END
                   WHERE id = ?""",
                (name, expires_on.isoformat(), meta_json, now, bool(changes), now, current.id),
            )
            if changes:
                self._audit(actor, "sync-update", current.id, "; ".join(changes))
        return "updated" if changes else "unchanged"

    def archive_missing(self, source: str, keep_external_ids: set[str], actor: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT id, name, external_id FROM reminders WHERE source = ? AND status = 'active' AND external_id IS NOT NULL",
            (source,),
        ).fetchall()
        archived = []
        with self.conn:
            for row in rows:
                if row["external_id"] in keep_external_ids:
                    continue
                self.conn.execute(
                    "UPDATE reminders SET status = 'archived', updated_at = ? WHERE id = ?", (utcnow_iso(), row["id"])
                )
                self._audit(actor, "archive", row["id"], f"{row['name']} no longer present in {source}")
                archived.append(row["name"])
        return archived

    def archive_external(self, external_id: str, actor: str, reason: str) -> None:
        r = self.get_by_external_id(external_id)
        if r and r.status == "active":
            with self.conn:
                self.conn.execute(
                    "UPDATE reminders SET status = 'archived', updated_at = ? WHERE id = ?", (utcnow_iso(), r.id)
                )
                self._audit(actor, "archive", r.id, f"{r.name}: {reason}")

    # ------------------------------------------------------------------ ssl targets

    def ssl_targets(self) -> list[SslTarget]:
        return [SslTarget(**dict(r)) for r in self.conn.execute("SELECT * FROM ssl_targets ORDER BY host, port")]

    def add_ssl_target(self, host: str, port: int, sni: str, name: str, notes: str, actor: str) -> SslTarget:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO ssl_targets (host, port, sni, name, notes, created_at, created_by) VALUES (?,?,?,?,?,?,?)",
                (host, port, sni or "", name or "", notes or "", utcnow_iso(), actor),
            )
            self._audit(actor, "ssl-add", None, f"{host}:{port}" + (f" (sni {sni})" if sni else ""))
        row = self.conn.execute("SELECT * FROM ssl_targets WHERE id = ?", (cur.lastrowid,)).fetchone()
        return SslTarget(**dict(row))

    def find_ssl_target(self, host: str, port: int, sni: str = "") -> SslTarget | None:
        row = self.conn.execute(
            "SELECT * FROM ssl_targets WHERE host = ? AND port = ? AND sni = ?", (host, port, sni or "")
        ).fetchone()
        return SslTarget(**dict(row)) if row else None

    def name_ssl_target(self, tid: int, name: str, actor: str) -> bool:
        """Give an unnamed target a name (a later scan identified it). Never renames a named one,
        which may have been named by hand. Returns whether it changed."""
        with self.conn:
            cur = self.conn.execute("UPDATE ssl_targets SET name = ? WHERE id = ? AND name = ''", (name, tid))
            if cur.rowcount:
                self._audit(actor, "ssl-name", None, f"target {tid}: {name}")
        return bool(cur.rowcount)

    def get_ssl_target(self, tid: int) -> SslTarget | None:
        row = self.conn.execute("SELECT * FROM ssl_targets WHERE id = ?", (tid,)).fetchone()
        return SslTarget(**dict(row)) if row else None

    def remove_ssl_target(self, tid: int, actor: str) -> None:
        with self.conn:
            t = self.get_ssl_target(tid)
            self.conn.execute("DELETE FROM ssl_targets WHERE id = ?", (tid,))
            if t:
                self._audit(actor, "ssl-remove", None, f"{t.host}:{t.port}")

    # ------------------------------------------------------------------ notifications

    def sent_stages(self, rid: int, expires_on: date) -> set[int]:
        rows = self.conn.execute(
            "SELECT stage FROM notifications WHERE reminder_id = ? AND expires_on = ? AND status = 'sent'",
            (rid, expires_on.isoformat()),
        )
        return {r["stage"] for r in rows}

    def delivered_keys(self, rid: int, expires_on: date, stage: int) -> set[str]:
        """Destinations that already received this stage in an earlier, partly failed attempt."""
        rows = self.conn.execute(
            "SELECT keys FROM notifications WHERE reminder_id = ? AND expires_on = ? AND stage = ? "
            "AND status IN ('sent', 'partial')",
            (rid, expires_on.isoformat(), stage),
        )
        return {k for r in rows for k in (r["keys"] or "").split(",") if k}

    def record_notification(
        self, r: Reminder, stage: int, status: str, channels: list[str], recipients: list[str], error: str = "",
        keys: list[str] | None = None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO notifications (reminder_id, reminder_name, expires_on, stage, status, channels,
                                              recipients, error, created_at, keys)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (r.id, r.name, r.expires_on.isoformat(), stage, status, ",".join(channels), ",".join(recipients),
                 error, utcnow_iso(), ",".join(keys or [])),
            )

    def history(self, limit: int = 50, rid: int | None = None) -> list[sqlite3.Row]:
        if rid is not None:
            return self.conn.execute(
                "SELECT * FROM notifications WHERE reminder_id = ? ORDER BY id DESC LIMIT ?", (rid, limit)
            ).fetchall()
        return self.conn.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # ------------------------------------------------------------------ audit + kv

    def _audit(self, actor: str, action: str, rid: int | None, details: str) -> None:
        self.conn.execute(
            "INSERT INTO audit (ts, actor, action, reminder_id, details) VALUES (?, ?, ?, ?, ?)",
            (utcnow_iso(), actor, action, rid, details),
        )

    def audit(self, actor: str, action: str, rid: int | None, details: str) -> None:
        """Record an audit entry on its own (committed immediately)."""
        with self.conn:
            self._audit(actor, action, rid, details)

    def audit_log(self, limit: int = 50, rid: int | None = None) -> list[sqlite3.Row]:
        if rid is not None:
            return self.conn.execute(
                "SELECT * FROM audit WHERE reminder_id = ? ORDER BY id DESC LIMIT ?", (rid, limit)
            ).fetchall()
        return self.conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def kv_get(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def acquire_lock(self, name: str, ttl_seconds: int, owner: str = "") -> bool:
        """Take a named lock shared by every process using this database (the daemon and any
        `expiry` command run by hand). False if someone else holds it. A lock left behind by a
        crashed process expires after ttl_seconds, so it can never wedge the service."""
        key = f"lock:{name}"
        now = datetime.now(timezone.utc)
        self.conn.execute("BEGIN IMMEDIATE")  # serialises the read-then-write across processes
        try:
            row = self.conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
            if row:
                held = json.loads(row["value"])
                if datetime.fromisoformat(held.get("until", "1970-01-01T00:00:00+00:00")) > now:
                    self.conn.rollback()
                    return False
            value = json.dumps({"until": (now + timedelta(seconds=ttl_seconds)).isoformat(), "owner": owner})
            self.conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self.conn.commit()
            return True
        except Exception:
            self.conn.rollback()
            raise

    def release_lock(self, name: str) -> None:
        self.kv_delete(f"lock:{name}")

    def kv_delete(self, key: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM kv WHERE key = ?", (key,))

    def kv_set(self, key: str, value: Any) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )


def _fmt(v: Any) -> str:
    if isinstance(v, list):
        return ",".join(v) or "-"
    if v == "" or v is None:
        return "-"
    return str(v)
