"""Naming an address found on the network: which server is 10.1.2.230?"""

import datetime as dt

from test_sslscan import NOT_AFTER, info, wildcard_server  # noqa: F401 - pytest fixture

from expiry.sources import identify, sslscan


def no_http(ip, port, timeout):
    return "", ""


def test_parse_http_reads_redirect_host_and_title():
    raw = (b"HTTP/1.1 302 Found\r\nServer: nginx\r\nLocation: https://jira.corp.test/secure/Dashboard\r\n\r\n"
           b"<html><head><title>\n  Jira &amp; Co\n</title></head>")
    assert identify.parse_http(raw) == ("jira.corp.test", "Jira & Co")


def test_parse_http_ignores_ip_and_relative_redirects_and_falls_back_to_server():
    assert identify.parse_http(b"HTTP/1.1 302 Found\r\nLocation: https://10.1.2.230/login\r\nServer: HP-iLO\r\n\r\n") \
        == ("", "HP-iLO")
    assert identify.parse_http(b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n") == ("", "")


def test_forward_dns_wins_and_prefers_a_name_the_certificate_covers():
    who = identify.identify("10.1.2.142", 443, info("*.corp.test"),
                            {"10.1.2.142": ["intranet-old.other.test", "wiki.corp.test"]},
                            reverse=lambda ip: "srv42.lan", http=lambda *a: ("x.corp.test", "Confluence"))
    assert (who.name, who.via, who.title) == ("wiki.corp.test", "dns", "Confluence")


def test_falls_back_through_ptr_redirect_and_certificate():
    wild = info("*.corp.test")
    assert identify.identify("10.0.0.1", 443, wild, {}, lambda ip: "srv1.corp.test", no_http).via == "ptr"
    who = identify.identify("10.0.0.1", 443, wild, {}, lambda ip: "", lambda *a: ("jira.corp.test", "Jira"))
    assert (who.name, who.via) == ("jira.corp.test", "redirect")
    who = identify.identify("10.0.0.1", 443, info("printer-2.office.lan"), {}, lambda ip: "", no_http)
    assert (who.name, who.via) == ("printer-2.office.lan", "certificate")
    # a wildcard, or a device name that is not a host name, names nothing
    assert identify.identify("10.0.0.1", 443, wild, {}, lambda ip: "", no_http).name == ""
    assert identify.identify("10.0.0.1", 443, info("HP LaserJet"), {}, lambda ip: "", no_http).name == ""


def test_a_domain_match_found_by_address_is_named_too(wildcard_server):  # noqa: F811
    """The bug that left rows as bare IPs: a certificate for one of your domains, found by sweeping
    a range, was returned before any name was looked for."""
    port = wildcard_server
    res = sslscan.scan(["corp.test"], networks=["127.0.0.1/32"], ports=[port], use_logs=False,
                       resolver=lambda h: [], reverse=lambda ip: "",
                       http=lambda *a: ("jira.corp.test", "System Dashboard - Jira"))
    [f] = res.found
    assert (f.host, f.name, f.name_via, f.title) == ("127.0.0.1", "jira.corp.test", "redirect",
                                                     "System Dashboard - Jira")
    assert f.described == f"127.0.0.1:{port} [jira.corp.test] · System Dashboard - Jira"


def test_tracked_hosts_name_the_address_they_resolve_to(wildcard_server):  # noqa: F811
    port = wildcard_server
    res = sslscan.scan(["corp.test"], networks=["127.0.0.1/32"], ports=[port], use_logs=False,
                       resolver=lambda h: ["127.0.0.1"] if h == "pay-portal.corp.test" else [],
                       reverse=lambda ip: "", http=no_http, known_hosts=["pay-portal.corp.test"])
    assert [(f.host, f.name, f.name_via) for f in res.found] == [("127.0.0.1", "pay-portal.corp.test", "dns")]


def test_http_hint_reads_a_real_tls_server(tmp_path):
    import socket
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            .not_valid_after(NOT_AFTER).sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        with ctx.wrap_socket(conn, server_side=True) as s:
            s.recv(4096)
            s.sendall(b"HTTP/1.1 301 Moved\r\nLocation: https://nas01.office.lan:5001/\r\n\r\n"
                      b"<title>Synology DiskStation</title>")

    threading.Thread(target=serve, daemon=True).start()
    try:
        assert identify.http_hint("127.0.0.1", port, 3) == ("nas01.office.lan", "Synology DiskStation")
    finally:
        srv.close()


def test_a_later_scan_names_an_address_tracked_without_one(store, wildcard_server):  # noqa: F811
    from zoneinfo import ZoneInfo

    port = wildcard_server
    tz = ZoneInfo("UTC")
    bare = sslscan.scan([], networks=["127.0.0.1/32"], ports=[port], use_logs=False, match_all=True,
                        reverse=lambda ip: "", http=no_http).found
    ids, addrs = set(), set()
    sslscan.track(store, bare, "test", tz, ids, addrs)
    assert store.find_ssl_target("127.0.0.1", port).name == ""
    named = sslscan.scan([], networks=["127.0.0.1/32"], ports=[port], use_logs=False, match_all=True,
                         reverse=lambda ip: "", http=lambda *a: ("ilo-db01.office.lan", "iLO 5"))
    assert sslscan.track(store, named.found, "test", tz, ids, addrs) == []
    label = f"SSL ilo-db01.office.lan (127.0.0.1:{port})"
    assert store.find_ssl_target("127.0.0.1", port).name == label
    assert store.get_by_external_id(f"ssl:127.0.0.1:{port}").name == label
    # a name typed by hand is never overwritten
    sslscan.track(store, sslscan.scan([], networks=["127.0.0.1/32"], ports=[port], use_logs=False,
                                      match_all=True, reverse=lambda ip: "",
                                      http=lambda *a: ("other.lan", "")).found, "test", tz, ids, addrs)
    assert store.find_ssl_target("127.0.0.1", port).name == label
