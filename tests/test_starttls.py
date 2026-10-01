"""STARTTLS and the legacy-TLS fallback, against real local servers.

Each server speaks just enough of its plain-text protocol to accept STARTTLS and then completes a
real TLS handshake with a self-signed certificate, so the probe is exercised end to end.
"""

import datetime as dt
import socket
import ssl
import struct
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from expiry.sources import sslcert
from expiry.sources.sslcert import parse_config_entry, probe, resolve_starttls

NOT_AFTER = dt.datetime(2027, 3, 9, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.test.local")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(77).not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            .not_valid_after(NOT_AFTER).sign(key, hashes.SHA256()))
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    return d / "c.pem", d / "k.pem"


def _serve(ctx, dialogue):
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    stop = threading.Event()

    def run():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            conn.settimeout(5)
            try:
                dialogue(conn)
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

    threading.Thread(target=run, daemon=True).start()
    return port, lambda: (stop.set(), srv.close())


def _server_ctx(cert_files, legacy_only=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*cert_files)
    if legacy_only:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def _line(conn):
    buf = b""
    while not buf.endswith(b"\r\n"):
        buf += conn.recv(1)
    return buf


def smtp(conn):
    conn.sendall(b"220 mail.test.local ESMTP\r\n")
    assert _line(conn).startswith(b"EHLO")
    conn.sendall(b"250-mail.test.local\r\n250-SIZE 1000\r\n250 STARTTLS\r\n")
    assert _line(conn) == b"STARTTLS\r\n"
    conn.sendall(b"220 Ready to start TLS\r\n")


def imap(conn):
    conn.sendall(b"* OK IMAP4rev1 ready\r\n")
    tag = _line(conn).split(b" ")[0]
    conn.sendall(tag + b" OK Begin TLS\r\n")


def pop3(conn):
    conn.sendall(b"+OK POP3 ready\r\n")
    assert _line(conn) == b"STLS\r\n"
    conn.sendall(b"+OK Begin TLS\r\n")


def ftp(conn):
    conn.sendall(b"220-Welcome\r\n220 FTP ready\r\n")
    assert _line(conn) == b"AUTH TLS\r\n"
    conn.sendall(b"234 AUTH TLS OK\r\n")


def ldap(conn):
    assert b"1.3.6.1.4.1.1466.20037" in conn.recv(4096)
    # ExtendedResponse, messageID 1, resultCode success, empty matchedDN and message
    conn.sendall(bytes.fromhex("300c02010178070a010004000400"))


def postgres(conn):
    assert conn.recv(8) == struct.pack("!II", 8, 80877103)
    conn.sendall(b"S")


@pytest.mark.parametrize("protocol,dialogue", [
    ("smtp", smtp), ("imap", imap), ("pop3", pop3), ("ftp", ftp), ("ldap", ldap), ("postgres", postgres),
])
def test_starttls_reads_the_certificate(cert_files, protocol, dialogue):
    port, stop = _serve(_server_ctx(cert_files), dialogue)
    try:
        info = probe("127.0.0.1", port, timeout=5, starttls=protocol)
    finally:
        stop()
    assert info.common_name == "mail.test.local"
    assert info.not_after == NOT_AFTER
    assert info.starttls == protocol
    assert info.meta()["starttls"] == protocol


def test_starttls_is_chosen_from_the_port():
    assert resolve_starttls(587, None) == "smtp"
    assert resolve_starttls(389, None) == "ldap"
    assert resolve_starttls(443, None) is None
    assert resolve_starttls(587, "none") is None, "an explicit 'none' wins over the port"
    with pytest.raises(ValueError):
        resolve_starttls(25, "gopher")


def test_config_entry_accepts_starttls():
    t = parse_config_entry({"host": "relay.example.com:2525", "starttls": "SMTP"})
    assert (t.port, t.starttls) == (2525, "smtp")
    with pytest.raises(ValueError):
        parse_config_entry({"host": "x.example.com", "starttls": "gopher"})


def test_a_refused_starttls_is_an_error_not_a_hang(cert_files):
    def refuse(conn):
        conn.sendall(b"220 hi\r\n")
        _line(conn)
        conn.sendall(b"250 OK\r\n")
        _line(conn)
        conn.sendall(b"454 TLS not available\r\n")
        raise OSError("done")

    port, stop = _serve(_server_ctx(cert_files), refuse)
    try:
        with pytest.raises(ConnectionError, match="smtp"):
            probe("127.0.0.1", port, timeout=5, starttls="smtp")
    finally:
        stop()


def _tls10_supported() -> bool:
    try:
        _server_ctx(("/nonexistent", "/nonexistent"), legacy_only=True)
    except (ssl.SSLError, ValueError):
        return False
    except OSError:
        return True  # got as far as loading the (missing) certificate: TLS 1.0 is configurable
    return True


@pytest.mark.skipif(not _tls10_supported(), reason="this OpenSSL build cannot serve TLS 1.0")
def test_a_tls_1_0_only_device_is_still_read(cert_files):
    """Old printers, iLO/iDRAC and switches only speak TLS 1.0/1.1; Python's default refuses them."""
    port, stop = _serve(_server_ctx(cert_files, legacy_only=True), lambda conn: None)
    try:
        info = probe("127.0.0.1", port, timeout=5)
    except ssl.SSLError as exc:
        pytest.skip(f"this OpenSSL build refuses TLS 1.0 entirely: {exc}")
    finally:
        stop()
    assert info.common_name == "mail.test.local"
    assert info.legacy_tls is True
    assert info.tls_version == "TLSv1"


def test_a_modern_server_does_not_use_the_fallback(cert_files):
    port, stop = _serve(_server_ctx(cert_files), lambda conn: None)
    try:
        info = probe("127.0.0.1", port, timeout=5)
    finally:
        stop()
    assert info.legacy_tls is False
    assert info.tls_version in ("TLSv1.2", "TLSv1.3")


def test_starttls_ports_table_is_consistent():
    assert set(sslcert.STARTTLS_PORTS.values()) <= set(sslcert.STARTTLS_PROTOCOLS)
