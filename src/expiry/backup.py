"""Consistent SQLite backups (safe while the daemon is running), retention and restore."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# scheduled/manual backups: expiry-20261001-023000.db ; safety copies before a restore use another
# prefix so retention never deletes them
_BACKUP_NAME = re.compile(r"^expiry-(\d{8}-\d{6})(?:-\d+)?\.db$")
PRE_RESTORE_PREFIX = "expiry-prerestore-"


@dataclass
class BackupInfo:
    path: Path
    size: int
    created: datetime


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _copy(src_path: str | Path, dst_path: Path, src_readonly: bool = False, standalone: bool = True) -> None:
    src_uri = Path(src_path).resolve().as_uri() + ("?mode=ro" if src_readonly else "")
    src = sqlite3.connect(src_uri, uri=True, timeout=30)
    try:
        dst = sqlite3.connect(dst_path, timeout=30)
        try:
            src.backup(dst)  # online backup API: consistent snapshot, works while others write
            if standalone:
                # the live database uses WAL; a backup must be one self-contained file (no -wal/-shm)
                dst.execute("PRAGMA journal_mode = DELETE")
        finally:
            dst.close()
    finally:
        src.close()


def verify(path: str | Path) -> int:
    """Check that a file is a healthy expiry database; return its number of reminders."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"backup not found: {p}")
    conn = sqlite3.connect(p.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise ValueError(f"{p.name}: integrity check failed: {result}")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if not {"reminders", "notifications", "audit"} <= tables:
            raise ValueError(f"{p.name}: not an expiry database")
        return conn.execute("SELECT COUNT(*) FROM reminders").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"{p.name}: not a valid database ({exc})") from exc
    finally:
        conn.close()


def create_backup(db_path: str, directory: str | Path, keep: int = 0, prefix: str = "expiry-") -> Path:
    """Write a verified snapshot of the database into `directory`; prune to `keep` newest if > 0."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    target = d / f"{prefix}{_stamp()}.db"
    n = 1
    while target.exists():
        target = d / f"{prefix}{_stamp()}-{n}.db"
        n += 1
    partial = target.with_name(target.name + ".partial")
    try:
        _copy(db_path, partial)
        verify(partial)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)
    if keep > 0:
        prune(d, keep)
    return target


def list_backups(directory: str | Path) -> list[BackupInfo]:
    d = Path(directory)
    if not d.is_dir():
        return []
    out = []
    for p in d.iterdir():
        m = _BACKUP_NAME.match(p.name)
        if m or (p.name.startswith(PRE_RESTORE_PREFIX) and p.suffix == ".db"):
            stamp = m.group(1) if m else p.stem[len(PRE_RESTORE_PREFIX):][:15]
            try:
                created = datetime.strptime(stamp, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
            except ValueError:
                created = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)
            out.append(BackupInfo(p, p.stat().st_size, created))
    return sorted(out, key=lambda b: (b.created, b.path.name), reverse=True)


def prune(directory: str | Path, keep: int) -> list[Path]:
    """Delete the oldest regular backups beyond `keep` (pre-restore safety copies are kept)."""
    regular = [b for b in list_backups(directory) if _BACKUP_NAME.match(b.path.name)]
    removed = []
    for b in regular[keep:]:
        b.path.unlink(missing_ok=True)
        removed.append(b.path)
    return removed


def resolve(name_or_path: str, directory: str | Path) -> Path:
    """Accept a full path or just a file name from `expiry backup list`."""
    p = Path(name_or_path)
    if p.is_file():
        return p
    candidate = Path(directory) / name_or_path
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(f"backup not found: {name_or_path} (see `expiry backup list`)")


def restore(backup_path: str | Path, db_path: str, directory: str | Path) -> Path:
    """Replace the live database with a backup. A safety copy of the current database is written
    first and returned. Safe while the daemon runs (SQLite locks during the copy)."""
    verify(backup_path)
    safety = create_backup(db_path, directory, keep=0, prefix=PRE_RESTORE_PREFIX)
    _copy(backup_path, Path(db_path), src_readonly=True, standalone=False)
    live = sqlite3.connect(db_path, timeout=30)
    try:
        live.execute("PRAGMA journal_mode = WAL")  # the live database stays in WAL mode
    finally:
        live.close()
    return safety
