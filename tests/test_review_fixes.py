"""Regression tests for issues found in the code review."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner
from conftest import TODAY, make_config

from expiry import scheduler
from expiry.checker import run_check
from expiry.cli import cli
from expiry.config import load_config, validate
from expiry.db import Store
from expiry.sources.sslcert import config_targets


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPIRY_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("EXPIRY_CONFIG", str(tmp_path / "missing.yaml"))
    runner = CliRunner()
    return lambda *a, input=None: runner.invoke(cli, list(a), input=input, catch_exceptions=False,
                                                prog_name="expiry")


def test_import_accepts_the_configured_date_format(run):
    r = run("import", "-", input="﻿name,expires_on,notes\nPayroll cert,31/12/2030,from Excel\nVPN,2031-01-15,\n")
    assert "Imported 2" in r.output
    items = {i["name"]: i["expires_on"] for i in json.loads(run("list", "--json").output)}
    assert items == {"Payroll cert": "2030-12-31", "VPN": "2031-01-15"}


def test_import_missing_file_explains_container_paths(run):
    r = run("import", "/home/alice/reminders.csv")
    assert r.exit_code == 2 and "expiry import - < reminders.csv" in r.output


def test_one_bad_ssl_host_entry_does_not_stop_the_others():
    cfg = make_config(sources__ssl__hosts=["good.example", "bad.example:abc", {"port": 443}, None,
                                           {"host": "lb.example", "port": 70000}, {"host": "ok.example", "port": 8443}])
    errors: list[str] = []
    targets = config_targets(cfg, errors)
    assert [(t.host, t.port) for t in targets] == [("good.example", 443), ("ok.example", 8443)]
    assert len(errors) == 4
    validation_errors, _ = validate(make_config(email__enabled=False, sources__ssl__hosts=["bad.example:abc"]))
    assert any("sources.ssl.hosts[0]" in e for e in validation_errors)


def test_invalid_cron_falls_back_to_default_instead_of_crashing():
    from zoneinfo import ZoneInfo
    cfg = make_config(schedule__sync="every hour please")
    trigger = scheduler.cron_trigger(cfg, "schedule.sync", ZoneInfo("UTC"))
    assert str(trigger) == str(scheduler.CronTrigger.from_crontab("0 */6 * * *", timezone=ZoneInfo("UTC")))


def test_missed_backup_and_scan_are_caught_up(tmp_path, monkeypatch):
    db = tmp_path / "e.db"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"database: {db.as_posix()}\nsources:\n  ssl:\n    scan:\n      enabled: true\n"
                        "      domains: [example.com]\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(scheduler, "_job_backup", lambda path: calls.append("backup"))
    monkeypatch.setattr(scheduler, "_job_scan", lambda path: calls.append("scan"))
    monkeypatch.setenv("EXPIRY_DB", str(db))

    scheduler._catch_up(str(cfg_file))           # never ran -> both catch up
    assert calls == ["backup", "scan"]

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with Store(str(db)) as s:
        s.kv_set("last_backup", {"at": now})
        s.kv_set("last_scan_attempt", now)       # a failed scan still counts as an attempt
    calls.clear()
    scheduler._catch_up(str(cfg_file))
    assert calls == []

    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="seconds")
    with Store(str(db)) as s:
        s.kv_set("last_backup", {"at": old})
    scheduler._catch_up(str(cfg_file))
    assert calls == ["backup"]                    # backup is a day overdue, scan is not a week overdue


def test_due_item_without_recipients_is_reported_not_logged_every_check(store):
    class Sender:
        def send(self, to, msg):
            raise AssertionError("nobody to send to")

    cfg = make_config(notify__emails=[], email__smtp__host="x", email__from="e@x.com")
    store.add("No recipients", TODAY + timedelta(days=1), "t")
    for _ in range(3):
        res = run_check(cfg, store, TODAY, email_sender=Sender())
        assert res.failed == 1 and any("no recipient" in e for e in res.errors)
    assert store.history() == []                  # no 'failed' row per check


def test_date_format_without_year_is_rejected_without_parsing():
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("error")            # the Python 3.13+ deprecation would fail here
        errors, _ = validate(make_config(date_format="%d/%m", email__enabled=False))
    assert any("date_format" in e for e in errors)


def test_example_config_is_valid_as_shipped():
    cfg = load_config("config/config.example.yaml")
    errors, _ = validate(cfg)
    assert [e for e in errors if not e.startswith(("email.", "entra."))] == []
