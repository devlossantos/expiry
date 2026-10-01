import json

import pytest
from click.testing import CliRunner

from expiry.cli import cli


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPIRY_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("EXPIRY_CONFIG", str(tmp_path / "missing.yaml"))
    monkeypatch.setenv("EXPIRY_ACTOR", "tester")
    runner = CliRunner()

    def _run(*args, input=None):
        return runner.invoke(cli, list(args), input=input, catch_exceptions=False, prog_name="expiry")
    return _run


def listing(run):
    return json.loads(run("list", "--json").output)


def test_add_list_edit_rm(run):
    r = run("add", "Payroll API cert", "2030-01-15", "renew", "via", "portal")
    assert r.exit_code == 0, r.output
    run("add", "github-pat", "+90d", "--notify", "dev@example.com")
    items = listing(run)
    assert [i["name"] for i in items] == ["github-pat", "Payroll API cert"]
    cert = items[1]
    assert cert["notes"] == "renew via portal" and cert["days_left"] > 0

    assert run("edit", str(cert["id"]), "--date", "2031-01-01", "--mute").exit_code == 0
    r = json.loads(run("show", str(cert["id"]), "--json").output)
    assert r["expires_on"] == "2031-01-01" and r["muted"] is True

    assert run("rm", str(cert["id"]), "-y").exit_code == 0
    assert [i["name"] for i in listing(run)] == ["github-pat"]

    audit = run("audit").output
    assert "tester" in audit and "remove" in audit


def test_irish_dates_in_and_out(run):
    assert run("add", "Irish", "31/03/2030").exit_code == 0
    assert "31/03/2030" in run("list").output
    assert json.loads(run("list", "--json").output)[0]["expires_on"] == "2030-03-31"  # JSON stays ISO
    run("edit", "1", "--date", "01/04/2030")
    assert "01/04/2030" in run("show", "1").output


def test_aliases_and_errors(run):
    run("add", "x", "2030-01-01")
    assert "x" in run("ls").output
    assert run("add", "y", "31-12-2030").exit_code == 2
    assert run("add", "y", "2030-01-01", "--notify", "nope").exit_code == 2
    assert run("rm", "999", "-y").exit_code == 1
    assert run("delete", "1", "-y").exit_code == 0


def test_export_import_roundtrip(run, tmp_path):
    run("add", "a", "2030-01-01", "--notes", "first")
    run("add", "b", "2030-02-01")
    data = run("export").output
    run("rm", "1", "2", "-y")
    r = run("import", "-", input=data)
    assert "Imported 2" in r.output
    r = run("import", "-", input=data)
    assert "Imported 0" in r.output and "skipped 2" in r.output
    csv_in = "name,expires_on,notes\nc,2030-03-01,from csv\n"
    assert "Imported 1" in run("import", "-", input=csv_in).output
    assert len(listing(run)) == 3


def test_check_dry_run_and_status(run):
    run("add", "soon", "+1d")
    r = run("check", "--dry-run")
    assert "soon" in r.output and "would be sent" in r.output
    r = run("status")
    assert r.exit_code == 0 and "not running" in r.output


def test_help_command(run):
    assert "Track the certificate" in run("help", "ssl", "add").output or \
        "Start tracking" in run("help", "ssl", "add").output
    assert "Usage: expiry" in run("--help").output


def test_audit_entries_from_cli_are_saved(run, tmp_path, monkeypatch):
    import os

    from expiry.db import Store
    s = Store(os.environ["EXPIRY_DB"])
    s.audit("tester", "scan", None, "checked 3 names")
    s.close()
    assert "checked 3 names" in run("audit").output  # visible from a new connection = committed


def test_ssl_scan_names_from_stdin_and_missing_file(run, monkeypatch):
    from expiry.sources import sslscan
    seen = {}

    def fake_scan(domains, names, networks, ports, use_logs, timeout, match_all=False):
        seen.update(domains=domains, names=names, ports=ports, match_all=match_all)
        return sslscan.ScanResult()

    monkeypatch.setattr(sslscan, "scan", fake_scan)
    r = run("ssl", "scan", "-d", "corp.test", "--names-file", "-", input='"HostName"\n"crm-prod"\nerp\n')
    assert r.exit_code == 0 and "2 name(s) read from stdin" in r.output
    assert seen == {"domains": ["corp.test"], "names": ["crm-prod", "erp"], "ports": [443, 8443, 9443],
                    "match_all": False}  # --domain given: keep that domain's certificates only
    r = run("ssl", "scan", "-d", "corp.test", "--names-file", "/nope/names.txt")
    assert r.exit_code == 2 and "/etc/expiry/" in r.output
