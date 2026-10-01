import datetime as dt
import socket
import ssl
import threading
from datetime import date, timedelta
from zoneinfo import ZoneInfo

import pytest
from conftest import TODAY, make_config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from expiry.checker import run_check
from expiry.sources import sslscan
from expiry.sources.sslcert import CertInfo, Target

NOT_AFTER = dt.datetime(2027, 3, 7, 13, 15, tzinfo=dt.timezone.utc)


@pytest.fixture
def wildcard_server(tmp_path):
    """A local HTTPS server presenting a *.corp.test wildcard certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.corp.test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            .not_valid_after(NOT_AFTER)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.corp.test"), x509.DNSName("corp.test")]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    yield port
    stop.set()
    srv.close()


def fake_dns(mapping):
    return lambda host: mapping.get(host, [])


def info(cn, san=(), sha="a" * 64):
    now = dt.datetime.now(dt.timezone.utc)
    return CertInfo("h", 443, "", now, now + timedelta(days=30), f"CN={cn}", cn, "Issuer", list(san), "1", sha)


def test_belongs_to_and_wildcard():
    assert sslscan.belongs_to(info("*.example.org"), ["example.org"])
    assert sslscan.belongs_to(info("www.example.org"), ["example.org"])
    assert sslscan.belongs_to(info("other.com", ["api.example.org"]), ["EXAMPLE.ORG"])
    assert not sslscan.belongs_to(info("notexample.org"), ["example.org"])
    assert not sslscan.belongs_to(info("example.org.evil.com"), ["example.org"])
    assert sslscan.is_wildcard(info("*.example.org")) and not sslscan.is_wildcard(info("www.example.org"))


def test_name_scan_finds_wildcard_hosts_and_groups_them(wildcard_server):
    port = wildcard_server
    dns = fake_dns({"wiki.corp.test": ["127.0.0.1"], "erp.corp.test": ["127.0.0.1"]})
    res = sslscan.scan(["corp.test"], names=["erp"], ports=[port], use_logs=False, timeout=3, resolver=dns)
    assert sorted(f.host for f in res.found) == ["erp.corp.test", "wiki.corp.test"]  # "wiki" is built in
    groups = res.by_certificate()
    assert len(groups) == 1  # one certificate, two locations
    locs = next(iter(groups.values()))
    assert sslscan.is_wildcard(locs[0].info) and locs[0].info.not_after == NOT_AFTER
    assert res.names_checked > 100


def test_other_domains_are_ignored(wildcard_server):
    dns = fake_dns({"wiki.example.com": ["127.0.0.1"]})
    res = sslscan.scan(["example.com"], ports=[wildcard_server], use_logs=False, resolver=dns)
    assert res.found == []  # the server's certificate is for corp.test, not example.com


def test_network_scan_finds_ip_only_server_and_skips_duplicates(wildcard_server):
    port = wildcard_server
    res = sslscan.scan(["corp.test"], networks=["127.0.0.1/32"], ports=[port], use_logs=False,
                       resolver=fake_dns({}), reverse=lambda ip: "")
    assert [(f.host, f.via, f.sni) for f in res.found] == [("127.0.0.1", "network", "")]
    # the same address found by name as well -> only the name is kept
    res = sslscan.scan(["corp.test"], networks=["127.0.0.1/32"], ports=[port], use_logs=False,
                       resolver=fake_dns({"wiki.corp.test": ["127.0.0.1"]}), reverse=lambda ip: "")
    assert [f.host for f in res.found] == ["wiki.corp.test"]


def test_network_range_limit():
    with pytest.raises(ValueError, match="smaller ranges"):
        sslscan.scan(["corp.test"], networks=["10.0.0.0/8"], use_logs=False)


def test_track_adds_once_and_respects_existing(store, wildcard_server):
    port = wildcard_server
    dns = fake_dns({"wiki.corp.test": ["127.0.0.1"], "portal.corp.test": ["127.0.0.1"]})
    res = sslscan.scan(["corp.test"], ports=[port], use_logs=False, resolver=dns)
    store.add_ssl_target("wiki.corp.test", port, "", "", "", "t")  # already tracked by hand
    ids, addrs = sslscan.tracked_state([Target("wiki.corp.test", port)], resolver=dns)
    added = sslscan.track(store, res.found, "scan", ZoneInfo("UTC"), ids, addrs)
    assert [f.host for f in added] == ["portal.corp.test"]
    r = store.get_by_external_id(f"ssl:portal.corp.test:{port}")
    assert r.expires_on == date(2027, 3, 7) and "wildcard" in r.notes
    assert sslscan.track(store, res.found, "scan", ZoneInfo("UTC"), ids, addrs) == []  # idempotent


def test_run_scheduled_report_only(store, wildcard_server, monkeypatch):
    port = wildcard_server
    monkeypatch.setattr(sslscan, "resolve", fake_dns({"wiki.corp.test": ["127.0.0.1"]}))
    cfg = make_config(sources__ssl__scan={"enabled": True, "domains": ["corp.test"], "ports": [port],
                                          "certificate_logs": False, "add": False, "names": [], "networks": []})
    result, added, new = sslscan.run_scheduled(cfg, store)
    assert added == [] and [f.host for f in new] == ["wiki.corp.test"] and store.ssl_targets() == []


class Sender:
    def __init__(self):
        self.sent = []

    def send(self, to, msg):
        self.sent.append((to, msg))


def test_servers_sharing_a_certificate_get_one_email(store):
    cfg = make_config(notify__emails=["ops@example.com"], email__smtp__host="x", email__from="e@x.com")
    meta = {"sha256": "f" * 64, "common_name": "*.corp.test", "issuer": "GoDaddy", "san": ["*.corp.test"]}
    exp = TODAY + timedelta(days=14)
    for host in ("wiki.corp.test", "portal.corp.test", "10.1.2.9"):
        store.add(f"SSL {host}", exp, "t", source="ssl", external_id=f"ssl:{host}:443", meta=meta)
    store.add("Other cert", exp, "t", source="ssl", external_id="ssl:other:443", meta={**meta, "sha256": "e" * 64})
    store.add("Manual item", exp, "t")
    s = Sender()
    res = run_check(cfg, store, TODAY, email_sender=s)
    assert res.sent == 5 and len(s.sent) == 3  # 3 servers -> 1 email, + other cert, + manual item
    grouped = next(m for _, m in s.sent if "servers" in m.subject)
    assert grouped.subject == "[Expiry] Certificate *.corp.test expires in 14 days (3 servers)"
    assert "wildcard certificate" in grouped.html and "SSL 10.1.2.9" in grouped.html


def test_scan_config_validation():
    from expiry.config import validate
    bad = make_config(email__enabled=False, sources__ssl__scan={
        "enabled": True, "domains": [], "networks": ["10.0.0.0/8", "nonsense"], "ports": [443],
        "schedule": "0 5 * * 1"})
    text = "\n".join(validate(bad)[0])
    assert "scan.domains" in text and "nonsense" in text and "too many" in text


def test_names_file_formats(tmp_path):
    from expiry.sources.sslscan import parse_names, read_names_file
    plain = "# app servers\ncrm-prod\nerp.example.com\n\nwiki   # the wiki\n"
    windows_csv = '﻿"HostName","RecordType","Timestamp"\n"crm-prod","A",""\n"@","A",""\n"_ldap._tcp","SRV",""\n"*.apps","A",""\n'
    bind = ("$ORIGIN example.com.\n; zone export\nexample.com. 3600 IN SOA ns1 hostmaster 1 2 3 4 5\n"
            "hr-portal.example.com. 3600 IN A 10.1.2.5\nCRM-PROD.example.com. 3600 IN CNAME x\n")
    assert parse_names(plain) == ["crm-prod", "erp.example.com", "wiki"]
    assert parse_names(windows_csv) == ["crm-prod", "apps"]
    assert parse_names(bind) == ["example.com", "hr-portal.example.com", "crm-prod.example.com"]
    f = tmp_path / "names.txt"
    f.write_text(plain, encoding="utf-8")
    assert read_names_file(str(f)) == ["crm-prod", "erp.example.com", "wiki"]


def test_names_file_names_are_scanned(wildcard_server, tmp_path):
    f = tmp_path / "export.csv"
    f.write_text('"HostName","RecordType"\n"crm-prod","A"\n', encoding="utf-8")
    dns = fake_dns({"crm-prod.corp.test": ["127.0.0.1"]})
    res = sslscan.scan(["corp.test"], names=sslscan.read_names_file(str(f)), ports=[wildcard_server],
                       use_logs=False, resolver=dns)
    assert [x.host for x in res.found] == ["crm-prod.corp.test"]


def test_default_ports_and_names_file_validation(tmp_path):
    from expiry.config import validate
    assert make_config().get("sources.ssl.scan.ports") == [443, 8443, 9443]
    c = make_config(email__enabled=False, sources__ssl__scan={
        "enabled": True, "domains": ["corp.test"], "names_file": str(tmp_path / "missing.txt"),
        "networks": [], "ports": [443], "schedule": "0 5 * * 1"})
    assert any("names_file" in e for e in validate(c)[0])
