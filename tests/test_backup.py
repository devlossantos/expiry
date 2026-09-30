import sqlite3
from datetime import date

import pytest

from expiry import backup
from expiry.db import Store


@pytest.fixture
def live_db(tmp_path):
    path = str(tmp_path / "data" / "expiry.db")
    s = Store(path)
    s.add("Cert A", date(2030, 1, 1), "t")
    s.add("Cert B", date(2030, 2, 1), "t")
    yield path, s
    s.close()


def test_backup_while_open_and_verify(live_db, tmp_path):
    path, store = live_db  # store keeps its connection open, like the running daemon
    b = backup.create_backup(path, tmp_path / "backups")
    assert b.name.startswith("expiry-") and b.suffix == ".db"
    assert backup.verify(b) == 2
    assert [p.name for p in (tmp_path / "backups").iterdir()] == [b.name]  # one file: no -wal/-shm/.partial
    assert sqlite3.connect(b).execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_retention_keeps_newest_and_spares_pre_restore(live_db, tmp_path):
    path, _ = live_db
    d = tmp_path / "backups"
    d.mkdir()
    for stamp in ("20260101-000000", "20260102-000000", "20260103-000000", "20260104-000000"):
        (d / f"expiry-{stamp}.db").write_bytes(b"x")
    (d / "expiry-prerestore-20250101-000000.db").write_bytes(b"x")
    (d / "notes.txt").write_text("unrelated")
    backup.prune(d, keep=2)
    names = sorted(p.name for p in d.iterdir())
    assert names == ["expiry-20260103-000000.db", "expiry-20260104-000000.db",
                     "expiry-prerestore-20250101-000000.db", "notes.txt"]


def test_restore_replaces_data_and_keeps_safety_copy(live_db, tmp_path):
    path, store = live_db
    d = tmp_path / "backups"
    snap = backup.create_backup(path, d)
    store.add("Added after backup", date(2031, 1, 1), "t")
    assert len(store.list()) == 3
    safety = backup.restore(snap, path, d)
    assert [r.name for r in Store(path).list()] == ["Cert A", "Cert B"]
    assert store.list()[-1].name == "Cert B"  # a connection opened before the restore sees the new data
    assert sqlite3.connect(path).execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert backup.verify(safety) == 3  # the pre-restore copy has the newer data
    assert safety.name.startswith(backup.PRE_RESTORE_PREFIX)


def test_verify_rejects_garbage(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"not a database at all" * 100)
    with pytest.raises(ValueError):
        backup.verify(bad)
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE t (x)").connection.commit()
    with pytest.raises(ValueError, match="not an expiry database"):
        backup.verify(other)


def test_resolve_by_name(live_db, tmp_path):
    path, _ = live_db
    b = backup.create_backup(path, tmp_path / "backups")
    assert backup.resolve(b.name, tmp_path / "backups") == b
    with pytest.raises(FileNotFoundError):
        backup.resolve("nope.db", tmp_path / "backups")
