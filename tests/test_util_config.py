from datetime import date, datetime, timezone

import pytest

from expiry.config import load_config, masked, validate
from expiry.util import format_date, parse_date, parse_graph_datetime, parse_host_port

from conftest import TODAY, make_config


@pytest.mark.parametrize("value,expected", [
    ("2027-01-15", date(2027, 1, 15)),
    ("+10d", date(2026, 10, 10)),
    ("+2w", date(2026, 10, 14)),
    ("+5m", date(2027, 2, 28)),   # Sep 30 + 5 months -> clamped to Feb 28
    ("+1y", date(2027, 9, 30)),
])
def test_parse_date(value, expected):
    assert parse_date(value, TODAY) == expected


@pytest.mark.parametrize("bad", ["2026-13-01", "01/02/2026", "tomorrow", "+3x", ""])
def test_parse_date_invalid(bad):
    with pytest.raises(ValueError):
        parse_date(bad, TODAY)


def test_parse_date_irish_format():
    irish = "%d/%m/%Y"
    assert parse_date("31/12/2026", TODAY, irish) == date(2026, 12, 31)
    assert parse_date("2026-12-31", TODAY, irish) == date(2026, 12, 31)  # ISO still accepted
    assert parse_date("+1d", TODAY, irish) == date(2026, 10, 1)
    with pytest.raises(ValueError, match="31/12/2026"):
        parse_date("12/31/2026", TODAY, irish)  # US order is rejected, error shows an example
    assert format_date(date(2026, 1, 5), irish) == "05/01/2026"
    assert parse_date("31 Dec 2026", TODAY, "%d %b %Y") == date(2026, 12, 31)


@pytest.mark.parametrize("fmt,ok", [("%d/%m/%Y", True), ("%Y-%m-%d", True), ("%d %b %Y", True),
                                    ("%d/%m", False), ("dd/mm/yyyy", False)])
def test_validate_date_format(fmt, ok):
    errors, _ = validate(make_config(date_format=fmt, email__enabled=False))
    assert (not any("date_format" in e for e in errors)) == ok


def test_validate_timezone():
    errors, _ = validate(make_config(timezone="Ireland/Dublin", email__enabled=False))
    assert any("Europe/Dublin" in e for e in errors)
    errors, _ = validate(make_config(timezone="Europe/Dublin", email__enabled=False))
    assert not any("timezone" in e for e in errors)


@pytest.mark.parametrize("text,expected", [
    ("example.com", ("example.com", 443)),
    ("Example.com:8443", ("example.com", 8443)),
    ("https://app.example.com/login?x=1", ("app.example.com", 443)),
    ("10.0.0.5:993", ("10.0.0.5", 993)),
    ("[2001:db8::1]:8443", ("2001:db8::1", 8443)),
    ("2001:db8::1", ("2001:db8::1", 443)),
])
def test_parse_host_port(text, expected):
    assert parse_host_port(text) == expected


def test_parse_graph_datetime_handles_7_fraction_digits():
    dt = parse_graph_datetime("2027-03-01T18:21:34.5163384Z")
    assert dt == datetime(2027, 3, 1, 18, 21, 34, 516338, tzinfo=timezone.utc)


def test_env_expansion_and_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET", "s3cr3t")
    monkeypatch.delenv("UNSET_VAR", raising=False)
    p = tmp_path / "c.yaml"
    p.write_text("entra:\n  client_secret: ${MY_SECRET}\n  tenant_id: ${UNSET_VAR:-fallback}\n"
                 "notify:\n  emails: [a@b.com]\n")
    cfg = load_config(str(p))
    assert cfg.get("entra.client_secret") == "s3cr3t"
    assert cfg.get("entra.tenant_id") == "fallback"
    assert cfg.get("notify.days_before") == [30, 14, 1]  # default kept
    assert masked(cfg.data)["entra"]["client_secret"] == "********"


def test_validate_reports_problems():
    cfg = make_config(notify__days_before=[30, -1], notify__emails=["not-an-email"],
                      sources__entra__enabled=True, schedule__check="bad cron")
    errors, _ = validate(cfg)
    text = "\n".join(errors)
    assert "days_before" in text
    assert "not-an-email" in text
    assert "entra.tenant_id" in text
    assert "schedule.check" in text
    assert "email.smtp.host" in text


def test_validate_ok(cfg):
    errors, warnings = validate(cfg)
    assert errors == []
