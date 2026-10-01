"""SSL/TLS certificate source: connects to hosts (domain or IP), reads the served certificate and
tracks its expiry date. Targets come from the config file and from `expiry ssl add`."""

from __future__ import annotations

import hashlib
import socket
import ssl
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


def probe(host: str, port: int = 443, sni: str = "", timeout: float = 10.0, verify: bool = False) -> CertInfo:
    """Fetch the leaf certificate served by host:port. Never fails on invalid/expired certs."""
    server_hostname = sni or (None if is_ip(host) else host)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(binary_form=True)
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
    )
    if verify:
        vctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
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
        target = Target(host, port, str(entry.get("sni") or ""), str(entry.get("name") or ""),
                        str(entry.get("notes") or ""))
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
                return t, probe(t.host, t.port, t.sni, self.timeout), None
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
