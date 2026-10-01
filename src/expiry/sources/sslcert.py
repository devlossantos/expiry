"""SSL/TLS certificate source: connects to hosts (domain or IP), reads the served certificate and
tracks its expiry date. Targets come from the config file and from `expiry ssl add`."""

from __future__ import annotations

import hashlib
import socket
import ssl
import struct
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

from expiry.config import Config
from expiry.sources.base import FetchResult, Item
from expiry.util import is_ip, parse_host_port


@dataclass
class Target:
    host: str
    port: int = 443
    sni: str = ""
    name: str = ""
    notes: str = ""
    starttls: str | None = None  # None = by port; "none" = direct TLS; or smtp, imap, ldap, ...

    @property
    def external_id(self) -> str:
        return external_id(self.host, self.port, self.sni)

    @property
    def label(self) -> str:
        return self.name or display_name(self.host, self.port, self.sni)


@dataclass
class CertInfo:
    host: str
    port: int
    sni: str
    not_before: datetime
    not_after: datetime
    subject: str
    common_name: str
    issuer: str
    san: list[str] = field(default_factory=list)
    serial: str = ""
    sha256: str = ""
    trusted: bool | None = None
    verify_error: str = ""
    tls_version: str = ""
    legacy_tls: bool = False   # only answered with the old-protocol fallback (TLS 1.0/1.1, weak ciphers)
    starttls: str = ""         # protocol upgraded with STARTTLS first ("" = direct TLS)

    def meta(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "sni": self.sni,
            "subject": self.subject,
            "common_name": self.common_name,
            "issuer": self.issuer,
            "san": self.san[:50],
            "serial": self.serial,
            "sha256": self.sha256,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "tls_version": self.tls_version,
            "legacy_tls": self.legacy_tls,
            "starttls": self.starttls,
        }


def external_id(host: str, port: int, sni: str = "") -> str:
    return f"ssl:{host}:{port}" + (f":{sni}" if sni else "")


def display_name(host: str, port: int, sni: str = "") -> str:
    h = f"[{host}]" if ":" in host else host
    name = f"SSL {h}" + ("" if port == 443 else f":{port}")
    return name + (f" ({sni})" if sni else "")


def _name_attr(name: x509.Name, oid) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else ""


# Ports where the service starts in plain text and is upgraded to TLS (STARTTLS) rather than speaking
# TLS from the first byte. Their certificates (mail relays, LDAP, databases) expire like any other
# and were invisible to a direct-TLS probe. Direct-TLS ports (465, 993, 995, 636) need no entry.
STARTTLS_PORTS = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3", 21: "ftp", 389: "ldap", 5432: "postgres"}
STARTTLS_PROTOCOLS = ("smtp", "imap", "pop3", "ftp", "ldap", "postgres")

# LDAPv3 ExtendedRequest for StartTLS (OID 1.3.6.1.4.1.1466.20037), message id 1
_LDAP_STARTTLS = bytes.fromhex("301d02010177188016") + b"1.3.6.1.4.1.1466.20037"


class StartTlsError(ConnectionError):
    pass


def _read_reply(sock: socket.socket, done) -> str:
    """Read text from the server until done(text) is true or the connection ends."""
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        text = buf.decode("latin-1")
        if done(text) or len(buf) > 65536:
            return text
    return buf.decode("latin-1")


def _last_line_done(code: str):
    """SMTP/FTP replies end with a line '<code> ...' (a '-' after the code means more lines follow)."""
    def done(text: str) -> bool:
        lines = [ln for ln in text.split("\r\n") if ln]
        return bool(lines) and text.endswith("\r\n") and len(lines[-1]) >= 4 and lines[-1][3] == " "
    return done


def starttls_upgrade(sock: socket.socket, protocol: str) -> None:
    """Speak just enough of the plain-text protocol to ask the server to switch to TLS."""
    if protocol == "smtp":
        _expect(_read_reply(sock, _last_line_done("220")), "220", protocol)
        sock.sendall(b"EHLO expiry.local\r\n")
        _expect(_read_reply(sock, _last_line_done("250")), "250", protocol)
        sock.sendall(b"STARTTLS\r\n")
        _expect(_read_reply(sock, _last_line_done("220")), "220", protocol)
    elif protocol == "ftp":
        _expect(_read_reply(sock, _last_line_done("220")), "220", protocol)
        sock.sendall(b"AUTH TLS\r\n")
        _expect(_read_reply(sock, _last_line_done("234")), "234", protocol)
    elif protocol == "imap":
        _expect(_read_reply(sock, lambda t: t.endswith("\r\n")), "* OK", protocol)
        sock.sendall(b"x1 STARTTLS\r\n")
        reply = _read_reply(sock, lambda t: "x1 " in t and t.endswith("\r\n"))
        if "x1 OK" not in reply:
            raise StartTlsError(f"imap: STARTTLS refused: {reply.strip()[:80]}")
    elif protocol == "pop3":
        _expect(_read_reply(sock, lambda t: t.endswith("\r\n")), "+OK", protocol)
        sock.sendall(b"STLS\r\n")
        _expect(_read_reply(sock, lambda t: t.endswith("\r\n")), "+OK", protocol)
    elif protocol == "ldap":
        sock.sendall(_LDAP_STARTTLS)
        reply = sock.recv(4096)
        # ExtendedResponse ([APPLICATION 24] = 0x78) carrying resultCode success (ENUMERATED 0)
        if b"\x78" not in reply or b"\x0a\x01\x00" not in reply:
            raise StartTlsError("ldap: StartTLS refused")
    elif protocol == "postgres":
        sock.sendall(struct.pack("!II", 8, 80877103))  # SSLRequest
        if sock.recv(1) != b"S":
            raise StartTlsError("postgres: server does not offer SSL")
    else:
        raise ValueError(f"unknown STARTTLS protocol '{protocol}'")


def _expect(reply: str, prefix: str, protocol: str) -> None:
    lines = [ln for ln in reply.split("\r\n") if ln]
    last = lines[-1] if lines else ""
    if not last.startswith(prefix) and not reply.startswith(prefix):
        raise StartTlsError(f"{protocol}: unexpected reply {(last or reply).strip()[:80]!r}")


def _modern_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _legacy_context() -> ssl.SSLContext:
    """For reading the certificate of old devices (printers, iLO/iDRAC, switches, appliances) that only
    speak TLS 1.0/1.1 or weak ciphers. Python's default refuses those, so the probe could not see
    exactly the certificates that get forgotten. Only used to READ the certificate: nothing is sent
    over the connection, so the weak protocol protects nothing that matters here."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():  # deprecated on purpose: this context exists to reach old servers
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError):
            pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _open(host: str, port: int, timeout: float, protocol: str | None) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    if protocol:
        try:
            starttls_upgrade(sock, protocol)
        except Exception:
            sock.close()
            raise
    return sock


def _handshake(host, port, server_hostname, timeout, protocol) -> tuple[bytes, str, bool]:
    """(leaf certificate DER, TLS version, used the legacy fallback)."""
    first_error: Exception | None = None
    for legacy, make in ((False, _modern_context), (True, _legacy_context)):
        ctx = make()
        try:
            with _open(host, port, timeout, protocol) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
                    return tls.getpeercert(binary_form=True) or b"", tls.version() or "", legacy
        except ssl.SSLError as exc:  # handshake refused: retry once with the old-protocol context
            first_error = first_error or exc
            continue
    raise first_error  # type: ignore[misc]


def resolve_starttls(port: int, starttls: str | None) -> str | None:
    """None = decide from the port; "" or "none" = direct TLS; a protocol name forces STARTTLS."""
    if starttls is None:
        return STARTTLS_PORTS.get(port)
    if starttls in ("", "none"):
        return None
    if starttls not in STARTTLS_PROTOCOLS:
        raise ValueError(f"starttls must be one of {', '.join(STARTTLS_PROTOCOLS)} or none")
    return starttls


def probe(host: str, port: int = 443, sni: str = "", timeout: float = 10.0, verify: bool = False,
          starttls: str | None = None) -> CertInfo:
    """Fetch the leaf certificate served by host:port. Never fails on invalid/expired certs.

    STARTTLS is used automatically on the usual plain-text ports (SMTP 25/587, IMAP 143, POP3 110,
    FTP 21, LDAP 389, PostgreSQL 5432); `starttls` overrides that. Servers that only accept TLS
    1.0/1.1 or weak ciphers are read with a second, legacy handshake, and flagged."""
    protocol = resolve_starttls(port, starttls)
    server_hostname = sni or (None if is_ip(host) else host)
    der, version, legacy = _handshake(host, port, server_hostname, timeout, protocol)
    if not der:
        raise ConnectionError("server did not present a certificate")
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    info = CertInfo(
        host=host,
        port=port,
        sni=sni,
        not_before=not_before,
        not_after=not_after,
        subject=cert.subject.rfc4514_string(),
        common_name=_name_attr(cert.subject, NameOID.COMMON_NAME),
        issuer=_name_attr(cert.issuer, NameOID.COMMON_NAME) or cert.issuer.rfc4514_string(),
        san=names,
        serial=format(cert.serial_number, "x"),
        sha256=hashlib.sha256(der).hexdigest(),
        tls_version=version,
        legacy_tls=legacy,
        starttls=protocol or "",
    )
    if verify:
        vctx = ssl.create_default_context()
        try:
            with _open(host, port, timeout, protocol) as sock:
                with vctx.wrap_socket(sock, server_hostname=sni or host):
                    info.trusted = True
        except ssl.SSLCertVerificationError as exc:
            info.trusted = False
            info.verify_error = exc.verify_message or str(exc)
        except (OSError, ssl.SSLError) as exc:
            info.verify_error = str(exc)
    return info


def parse_config_entry(entry: Any) -> Target:
    """One sources.ssl.hosts entry ("host", "host:port" or a mapping) -> Target. Raises ValueError."""
    if isinstance(entry, dict):
        if not entry.get("host"):
            raise ValueError(f"entry without 'host': {entry}")
        host, port = parse_host_port(str(entry["host"]))
        if entry.get("port") not in (None, ""):
            port = int(entry["port"])
        starttls = entry.get("starttls")
        starttls = None if starttls in (None, "") else str(starttls).lower()
        resolve_starttls(port, starttls)  # raises ValueError on an unknown protocol
        target = Target(host, port, str(entry.get("sni") or ""), str(entry.get("name") or ""),
                        str(entry.get("notes") or ""), starttls)
    elif isinstance(entry, (str, int)) and str(entry).strip():
        target = Target(*parse_host_port(str(entry)))
    else:
        raise ValueError(f"not a host: {entry!r}")
    if not 0 < target.port < 65536:
        raise ValueError(f"invalid port {target.port} in {entry!r}")
    return target


def config_targets(cfg: Config, errors: list[str] | None = None) -> list[Target]:
    """Targets from sources.ssl.hosts. Invalid entries are skipped (and reported in `errors`), so one
    typo doesn't stop the other hosts from being checked."""
    out: list[Target] = []
    for i, entry in enumerate(cfg.get("sources.ssl.hosts") or []):
        try:
            out.append(parse_config_entry(entry))
        except (ValueError, TypeError) as exc:
            if errors is not None:
                errors.append(f"sources.ssl.hosts[{i}]: {exc}")
    return out


class SslSource:
    name = "ssl"

    def __init__(self, cfg: Config, store):
        self.cfg = cfg
        self.store = store
        self.timeout = float(cfg.get("sources.ssl.timeout") or 10)
        self.tz = ZoneInfo(cfg.timezone)

    def targets(self, errors: list[str] | None = None) -> list[Target]:
        seen: dict[str, Target] = {}
        for t in config_targets(self.cfg, errors):
            seen[t.external_id] = t
        for t in self.store.ssl_targets():
            seen.setdefault(external_id(t.host, t.port, t.sni), Target(t.host, t.port, t.sni, t.name, t.notes))
        return list(seen.values())

    def item_for(self, target: Target, info: CertInfo) -> Item:
        return Item(
            external_id=target.external_id,
            name=target.label,
            expires_on=info.not_after.astimezone(self.tz).date(),
            meta=info.meta(),
            notes=target.notes,
        )

    def fetch(self) -> FetchResult:
        result = FetchResult()
        targets = self.targets(result.errors)
        if not targets:
            return result

        def run(t: Target):
            try:
                return t, probe(t.host, t.port, t.sni, self.timeout, starttls=t.starttls), None
            except Exception as exc:  # noqa: BLE001
                return t, None, exc

        with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
            for t, info, exc in pool.map(run, targets):
                if info is None:
                    result.errors.append(f"{t.label}: {exc}")
                    result.keep_ids.add(t.external_id)
                else:
                    result.items.append(self.item_for(t, info))
        return result


def discover(domain: str, timeout: float = 60) -> list[str]:
    """Find host names under a domain using Certificate Transparency logs (crt.sh)."""
    domain = domain.lower().strip().lstrip("*.").rstrip(".")
    resp = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=timeout,
                        headers={"User-Agent": "expiry-cli"})
    resp.raise_for_status()
    now = datetime.now(timezone.utc).isoformat()
    names: set[str] = {domain}
    for entry in resp.json():
        if (entry.get("not_after") or "9999") < now[:19]:
            continue  # only names from certificates that are still valid
        for n in (entry.get("name_value") or "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n and (n == domain or n.endswith("." + domain)) and "@" not in n:
                names.add(n)
    return sorted(names)
