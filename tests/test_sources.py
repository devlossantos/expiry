import datetime as dt
import ssl
import threading
from datetime import date, timedelta

import pytest
from conftest import make_config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from expiry.sources import sync_source
from expiry.sources.base import FetchResult, Item
from expiry.sources.entra import EntraSource
from expiry.sources.sslcert import SslSource, probe


class FakeGraph:
    def __init__(self, apps, sps=(), owners=None):
        self.apps, self.sps, self.owners = apps, list(sps), owners or {}

    def get_all(self, path, params=None):
        if path == "/applications":
            return iter(self.apps)
        if path == "/servicePrincipals":
            return iter(self.sps)
        if path.endswith("/owners"):
            return iter(self.owners.get(path.split("/")[2], []))
        raise AssertionError(path)


def future(days):
    return (dt.datetime.now(dt.timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.1234567Z")


APPS = [
    {"id": "obj-1", "appId": "app-1", "displayName": "Payroll API",
     "passwordCredentials": [{"keyId": "k1", "displayName": "prod", "endDateTime": future(20)},
                             {"keyId": "k-old", "displayName": "ancient", "endDateTime": future(-400)}],
     "keyCredentials": [{"keyId": "c1", "customKeyIdentifier": "AB", "endDateTime": future(200), "usage": "Sign"},
                        {"keyId": "c2", "customKeyIdentifier": "AB", "endDateTime": future(200),
                         "usage": "Verify"}]},
    {"id": "obj-2", "appId": "app-2", "displayName": "test-sandbox",
     "passwordCredentials": [{"keyId": "k2", "hint": "abc", "endDateTime": future(5)}], "keyCredentials": []},
]


def test_entra_items_filtering_and_dedup():
    cfg = make_config(sources__entra__enabled=True, sources__entra__exclude=["test-*"])
    res = EntraSource(cfg, graph=FakeGraph(APPS)).fetch()
    names = sorted(i.name for i in res.items)
    # excluded app skipped, long-expired secret skipped, Sign/Verify cert pair collapsed to one
    assert names == ["Payroll API [cert: c1]", "Payroll API [secret: prod]"]
    secret = next(i for i in res.items if "secret" in i.name)
    assert secret.external_id == "entra:app:obj-1:secret:k1"
    assert "app-1" in secret.meta["portal_url"]


def test_entra_owners_and_service_principals():
    sps = [{"id": "sp-1", "appId": "app-9", "displayName": "SAML App", "servicePrincipalType": "Application",
            "passwordCredentials": [], "keyCredentials": [{"keyId": "s1", "endDateTime": future(60)}]},
           {"id": "sp-2", "appId": "mi", "displayName": "MI", "servicePrincipalType": "ManagedIdentity",
            "passwordCredentials": [], "keyCredentials": [{"keyId": "m1", "endDateTime": future(60)}]}]
    owners = {"obj-2": [{"mail": "owner@example.com"}, {"userPrincipalName": "guest#EXT#@x.onmicrosoft.com"}]}
    cfg = make_config(sources__entra__enabled=True, sources__entra__include_service_principals=True,
                      sources__entra__notify_owners=True)
    res = EntraSource(cfg, graph=FakeGraph(APPS, sps, owners)).fetch()
    by_name = {i.name: i for i in res.items}
    assert "SAML App [cert: s1]" in by_name
    assert not any(n.startswith("MI") for n in by_name)
    assert by_name["test-sandbox [secret: abc***]"].meta["owners"] == ["owner@example.com"]


class ListSource:
    name = "entra"

    def __init__(self, items, keep=()):
        self.result = FetchResult(items=items, keep_ids=set(keep))

    def fetch(self):
        return self.result


def test_sync_create_update_archive_ignore(store):
    d = date(2027, 1, 1)
    a, b = Item("x:a", "A", d), Item("x:b", "B", d)
    r = sync_source(ListSource([a, b]), store)
    assert (r.created, r.updated) == (2, 0)
    # renewal of A, B disappears
    r = sync_source(ListSource([Item("x:a", "A", date(2028, 1, 1))]), store)
    assert (r.updated, r.archived) == (1, 1)
    assert store.get_by_external_id("x:b").status == "archived"
    # user removes A -> ignored, never resurrected
    store.remove(store.get_by_external_id("x:a").id, "t")
    r = sync_source(ListSource([Item("x:a", "A", date(2028, 1, 1))]), store)
    assert r.ignored == 1 and store.get_by_external_id("x:a").status == "ignored"
    # B reappears -> active again
    sync_source(ListSource([b]), store)
    assert store.get_by_external_id("x:b").status == "active"


def test_sync_failure_does_not_archive(store):
    sync_source(ListSource([Item("x:a", "A", date(2027, 1, 1))]), store)

    class Boom:
        name = "entra"

        def fetch(self):
            raise RuntimeError("graph down")

    r = sync_source(Boom(), store)
    assert r.failed and store.get_by_external_id("x:a").status == "active"


def test_notes_and_mute_survive_sync(store):
    sync_source(ListSource([Item("x:a", "A", date(2027, 1, 1))]), store)
    rid = store.get_by_external_id("x:a").id
    store.update(rid, "t", notes="rotate via pipeline", muted=True)
    sync_source(ListSource([Item("x:a", "A renamed", date(2027, 6, 1))]), store)
    r = store.get(rid)
    assert (r.name, r.notes, r.muted, r.expires_on) == ("A renamed", "rotate via pipeline", True, date(2027, 6, 1))


# ---------------------------------------------------------------- real TLS handshake against a local server


@pytest.fixture
def tls_server(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    not_after = dt.datetime(2027, 5, 17, 12, 0, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(4242).not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.local")]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    import socket
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

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port, not_after
    stop.set()
    srv.close()


def test_probe_reads_self_signed_certificate(tls_server):
    port, not_after = tls_server
    info = probe("127.0.0.1", port, sni="test.local", timeout=5, verify=True)
    assert info.not_after == not_after
    assert info.common_name == "test.local"
    assert info.san == ["test.local"]
    assert info.trusted is False  # self-signed


def test_ssl_source_sync(store, tls_server):
    port, _ = tls_server
    store.add_ssl_target("127.0.0.1", port, "test.local", "", "lb cert", "t")
    cfg = make_config(sources__ssl__hosts=["127.0.0.1:1"])  # unreachable config host
    res = SslSource(cfg, store).fetch()
    assert len(res.items) == 1 and res.items[0].expires_on == date(2027, 5, 17)
    assert res.items[0].name == "SSL 127.0.0.1:%d (test.local)" % port
    assert len(res.errors) == 1 and "ssl:127.0.0.1:1" in res.keep_ids
