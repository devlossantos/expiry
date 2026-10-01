"""Find where your certificates are installed, so they don't have to be typed in one by one.

Candidates come from three places:
  * name guessing   - <common name>.<domain> for a built-in list of typical server names plus your own
                      names, resolved with the server's DNS (so internal names work on your network)
  * network ranges  - every address of the CIDR ranges you list, on the ports you list (opt-in); the
                      reverse-DNS name is used to ask for the right certificate
  * certificate logs - public Certificate Transparency logs (crt.sh), for public host names

Only certificates that belong to one of your domains are kept (their name or SANs match the domain,
including wildcards such as *.example.com). With no domain configured (match: all), every certificate
found on the scanned networks is kept instead: the self-signed certificates of printers, consoles and
appliances are exactly the ones nobody tracks. Results are grouped by certificate, so a wildcard
installed on several servers shows up once with all its locations.

The networks themselves can be discovered rather than listed: see netdiscover.py.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from expiry.sources.sslcert import CertInfo, Target, discover, external_id, probe

log = logging.getLogger(__name__)

# Typical server names. Kept generic on purpose; add your own with --name / sources.ssl.scan.names.
COMMON_NAMES = """
www www1 www2 web web1 web2 m mobile app apps api api2 gateway gw portal my account accounts login sso
auth id identity adfs sts idp mail webmail email owa exchange autodiscover smtp imap pop mx mx1 mx2
remote vpn sslvpn ra citrix rdp rdweb workspace desktop intranet extranet internal corp office
sharepoint teams wiki docs doc kb help helpdesk support servicedesk itsm jira confluence git gitlab
github bitbucket jenkins ci build artifactory nexus registry harbor sonar grafana kibana prometheus
monitor monitoring nagios zabbix status noc ops admin manage management console dashboard panel cpanel
plesk ftp sftp files file share shares cloud drive nextcloud owncloud backup storage nas san vcenter
esxi vsphere hyperv proxmox firewall fw pfsense fortigate paloalto router switch wifi wlan radius ldap
ldaps dc ad dns ns ns1 ns2 ntp crm erp sap hr payroll finance billing pay payments shop store order
orders cart checkout cdn static assets media img images video stream meet conference chat events
news blog careers jobs partner partners customer customers client clients b2b edi test testing dev
development staging stage uat qa demo sandbox preprod prod live new old legacy beta alpha lab
""".split()

MAX_NETWORK_TARGETS = 65536  # addresses x ports per scan, to avoid scanning huge ranges by mistake
DEFAULT_PORTS = [443, 8443, 9443]  # HTTPS + the two most common alternative HTTPS ports for apps


@dataclass
class Found:
    host: str          # what to track: a DNS name, or an IP for network finds
    port: int
    sni: str           # server name requested ("" = none)
    address: str       # IP that answered
    info: CertInfo
    via: str           # "name" | "network" | "logs"
    name: str = ""     # host name for an address-only find (see identify.py)
    name_via: str = "" # how that name was found: dns | ptr | redirect | certificate
    title: str = ""    # what the server says it is: its web page title or Server header

    @property
    def external_id(self) -> str:
        return external_id(self.host, self.port, self.sni)

    @property
    def location(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{h}:{self.port}" + (f" ({self.sni})" if self.sni and self.sni != self.host else "")

    @property
    def described(self) -> str:
        """The location plus whatever identifies the server: [name] and its page title."""
        out = self.location
        if self.name and self.name != self.host and self.name != self.sni:
            out += f" [{self.name}]"
        return out + (f" · {self.title}" if self.title else "")


@dataclass
class ScanResult:
    found: list[Found] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    names_checked: int = 0
    addresses_checked: int = 0
    networks: list[str] = field(default_factory=list)  # discovered networks, with their reasons

    def by_certificate(self) -> dict[str, list[Found]]:
        groups: dict[str, list[Found]] = {}
        for f in sorted(self.found, key=lambda f: (f.info.not_after, f.host, f.port)):
            groups.setdefault(f.info.sha256, []).append(f)
        return groups


_SKIP_TOKENS = {"hostname", "name", "@", "*", "$origin", "$ttl", ";"}


def read_names_file(path: str) -> list[str]:
    """Host names from a file: one per line, or the first column of a DNS export.

    Accepts plain lists (`crm-prod` or `crm-prod.example.com`), comments (#, ;), a Windows DNS
    CSV export (`Get-DnsServerResourceRecord ... | Export-Csv`, column HostName) and BIND zone
    listings (`crm-prod.example.com. 3600 IN A 10.1.2.5`)."""
    from pathlib import Path

    return parse_names(Path(path).read_text(encoding="utf-8-sig", errors="replace"))


def parse_names(text: str) -> list[str]:
    """See read_names_file."""
    names: list[str] = []
    for raw in text.lstrip("﻿").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(";"):
            continue
        first = line.split(",", 1)[0] if "," in line else line.split()[0]
        token = first.strip().strip('"').strip("'").strip().rstrip(".").lower()
        if (not token or token in _SKIP_TOKENS or token.startswith("$") or token.startswith("_")
                or any(c in token for c in " /\\:")):
            continue
        if token.startswith("*."):
            token = token[2:]
        names.append(token)
    return list(dict.fromkeys(names))


def cert_names(info: CertInfo) -> list[str]:
    return [n.lower() for n in ([info.common_name] + list(info.san)) if n]


def is_wildcard(info: CertInfo) -> bool:
    return any(n.startswith("*.") for n in cert_names(info))


def belongs_to(info: CertInfo, domains: list[str]) -> bool:
    """True if the certificate is issued for one of the domains or a name under it."""
    doms = [d.lower().strip().lstrip("*.").rstrip(".") for d in domains if d]
    for name in cert_names(info):
        n = name[2:] if name.startswith("*.") else name
        if any(n == d or n.endswith("." + d) for d in doms):
            return True
    return False


def name_candidates(domain: str, extra: list[str] | None = None, use_logs: bool = True,
                    warnings: list[str] | None = None) -> dict[str, str]:
    """host name -> how it was found ("name" or "logs")."""
    domain = domain.lower().strip().lstrip("*.").rstrip(".")
    out = {domain: "name"}
    for n in COMMON_NAMES + [x.strip().lower() for x in (extra or []) if x.strip()]:
        out[n if n.endswith("." + domain) or n == domain else f"{n}.{domain}"] = "name"
    if use_logs:
        try:
            for n in discover(domain, timeout=45):
                out.setdefault(n, "logs")
        except Exception as exc:  # noqa: BLE001 - crt.sh is often slow or down; names still work
            if warnings is not None:
                warnings.append(f"certificate logs (crt.sh) unavailable for {domain}: {str(exc)[:80]}")
    return out


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({i[4][0] for i in infos})


def reverse_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except OSError:
        return ""


def network_addresses(networks: list[str], limit: int = MAX_NETWORK_TARGETS) -> list[str]:
    nets = [ipaddress.ip_network(n.strip(), strict=False) for n in networks]
    total = sum(n.num_addresses for n in nets)
    if total > limit:  # check before expanding: a /8 is 16 million addresses
        raise ValueError(f"{total} addresses: more than {limit}; scan smaller ranges")
    out: list[str] = []
    for n in nets:
        hosts = [n.network_address] if n.num_addresses == 1 else list(n.hosts())
        out.extend(str(a) for a in hosts)
    return list(dict.fromkeys(out))


def scan(domains: list[str], names: list[str] | None = None, networks: list[str] | None = None,
         ports: list[int] | None = None, use_logs: bool = True, timeout: float = 3.0, workers: int = 32,
         resolver=None, reverse=None, match_all: bool = False, known_hosts: list[str] | None = None,
         http=None) -> ScanResult:
    """match_all: keep every certificate found on `networks`, not only those for `domains`.
    known_hosts: names already tracked; with every name this scan resolves, they put a name to an
    address found on the network (see identify.py)."""
    from expiry.sources import identify as ident

    resolver = resolver or resolve  # looked up at call time (patchable in tests)
    reverse = reverse or reverse_name
    result = ScanResult()
    ports = [int(p) for p in (ports or DEFAULT_PORTS)]
    doms = [d for d in domains if d]
    # validate the ranges first, so a too-large range fails immediately
    addresses = network_addresses(networks or [], MAX_NETWORK_TARGETS // len(ports))
    result.addresses_checked = len(addresses)

    # ---- names: resolve, then connect to each address asking for that name
    candidates: dict[str, str] = {}
    for d in doms:
        candidates.update(name_candidates(d, names, use_logs, result.warnings))
    result.names_checked = len(candidates)
    with ThreadPoolExecutor(workers) as pool:
        resolved = dict(zip(candidates, pool.map(resolver, candidates), strict=True))
    name_tasks = [(host, ip, port, candidates[host]) for host, ips in resolved.items() for ip in ips[:4]
                  for port in ports]

    def try_name(task):
        host, ip, port, via = task
        try:
            info = probe(ip, port, host, timeout)
        except Exception:  # noqa: BLE001 - nothing listening / not TLS
            return None
        return Found(host, port, "", ip, info, via) if belongs_to(info, doms) else None

    # every address a name resolved to, so a network find can be named (identify.py)
    extra = [h for h in dict.fromkeys(known_hosts or []) if h not in resolved and not _is_ip(h)]
    if addresses and extra:
        with ThreadPoolExecutor(workers) as pool:
            resolved_extra = dict(zip(extra, pool.map(resolver, extra), strict=True))
    else:
        resolved_extra = {}
    forward: dict[str, list[str]] = {}
    for host, ips in {**resolved, **resolved_extra}.items():
        for ip in ips:
            forward.setdefault(ip, []).append(host.lower().rstrip("."))

    # ---- networks: connect without a name; if the certificate isn't ours, retry with the reverse-DNS name

    def try_address(task):
        ip, port = task
        try:
            info = probe(ip, port, "", timeout)
        except Exception:  # noqa: BLE001
            return None
        ptr_cache: list[str] = []

        def ptr(_ip: str = ip) -> str:
            if not ptr_cache:
                ptr_cache.append(reverse(ip))
            return ptr_cache[0]

        def named(f: Found) -> Found:
            who = ident.identify(ip, port, f.info, forward, ptr, http, timeout)
            f.title = who.title
            if f.sni:  # already reached by its reverse-DNS name
                f.name, f.name_via = f.sni, "ptr"
            else:
                f.name, f.name_via = who.name, who.via
            return f

        if doms and belongs_to(info, doms):
            return named(Found(ip, port, "", ip, info, "network"))
        name = ptr()
        if name and doms and any(name == d or name.endswith("." + d) for d in doms):
            try:
                by_ptr = probe(ip, port, name, timeout)
            except Exception:  # noqa: BLE001
                by_ptr = None
            if by_ptr is not None and belongs_to(by_ptr, doms):
                return named(Found(ip, port, name, ip, by_ptr, "network"))
        if match_all:
            return named(Found(ip, port, "", ip, info, "network"))
        return None

    with ThreadPoolExecutor(workers) as pool:
        by_name = [f for f in pool.map(try_name, name_tasks) if f]
        by_net = [f for f in pool.map(try_address, [(a, p) for a in addresses for p in ports]) if f]

    # one entry per name:port (several addresses of the same name -> keep one per certificate)
    seen: set[tuple] = set()
    for f in by_name:
        key = (f.host, f.port, f.info.sha256)
        if key not in seen:
            seen.add(key)
            result.found.append(f)
    # a network hit already covered by a name (same address, port and certificate) adds nothing
    covered = {(f.address, f.port, f.info.sha256) for f in result.found}
    result.found += [f for f in by_net if (f.address, f.port, f.info.sha256) not in covered]
    return result


def tracked_state(targets: list[Target], resolver=None) -> tuple[set[str], set[tuple[str, int]]]:
    """(external ids already tracked, (address, port) pairs they point to)."""
    resolver = resolver or resolve
    ids = {t.external_id for t in targets}
    with ThreadPoolExecutor(16) as pool:
        addrs = list(pool.map(lambda t: [t.host] if _is_ip(t.host) else resolver(t.host), targets))
    return ids, {(a, t.port) for t, ips in zip(targets, addrs, strict=True) for a in ips}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_tracked(f: Found, ids: set[str], addresses: set[tuple[str, int]]) -> bool:
    if f.external_id in ids:
        return True
    return f.via == "network" and (f.address, f.port) in addresses  # same server, already tracked by name


def track(store, found: list[Found], actor: str, tz, ids: set[str], addresses: set[tuple[str, int]]) -> list[Found]:
    """Add found locations as SSL targets (+ their reminders). Returns what was newly added."""
    added = []
    for f in found:
        label = scan_label(f)
        existing = store.find_ssl_target(f.host, f.port, f.sni)
        if existing is not None and label and not existing.name:
            # tracked by address before it could be named: name it now (the reminder follows on sync)
            if store.name_ssl_target(existing.id, label, actor):
                t = Target(f.host, f.port, f.sni, label, existing.notes)
                store.upsert_external("ssl", t.external_id, t.label, f.info.not_after.astimezone(tz).date(),
                                      f.info.meta(), actor, notes=existing.notes)
        if existing is not None or is_tracked(f, ids, addresses):
            continue
        note = f"found by scan ({f.via})" + (" · wildcard" if is_wildcard(f.info) else "")
        store.add_ssl_target(f.host, f.port, f.sni, label, note, actor)
        t = Target(f.host, f.port, f.sni, label, note)
        store.upsert_external("ssl", t.external_id, t.label, f.info.not_after.astimezone(tz).date(),
                              f.info.meta(), actor, notes=note)
        ids.add(f.external_id)
        addresses.add((f.address, f.port))
        added.append(f)
    return added


def scan_label(f: Found) -> str:
    """'SSL jira.example.com (10.1.2.230)' for an address found on the network; '' when the
    address is all there is (the default display name is used then)."""
    what = f.name or f.title
    if not what or f.via != "network":
        return ""
    return f"SSL {what} ({f.host}{'' if f.port == 443 else f':{f.port}'})"


def match_all(opts: dict, domains: list[str]) -> bool:
    """sources.ssl.scan.match: 'all', 'domains', or 'auto' (all when no domain is configured)."""
    mode = str(opts.get("match") or "auto").lower()
    return mode == "all" or (mode == "auto" and not domains)


def scan_networks(cfg, store, ports: list[int], warnings: list[str]) -> tuple[list[str], list]:
    """The networks to scan: sources.ssl.scan.networks plus, with discover_networks on, the private
    networks this server can reach (trimmed to what is left of the per-scan budget).
    Returns (CIDR strings, the Discovered entries that were used)."""
    from expiry.sources import netdiscover
    from expiry.sources.sslcert import SslSource

    opts = cfg.get("sources.ssl.scan") or {}
    configured = [str(n) for n in (opts.get("networks") or [])]
    if not opts.get("discover_networks", True):
        return configured, []
    budget = MAX_NETWORK_TARGETS // max(len(ports), 1)
    used = sum(ipaddress.ip_network(n, strict=False).num_addresses for n in configured)
    known = [t.host for t in SslSource(cfg, store).targets()]
    found = netdiscover.discover(known, int(opts.get("discover_prefix") or 24),
                                 list(opts.get("exclude_networks") or []), warnings=warnings)
    already = [ipaddress.ip_network(n, strict=False) for n in configured]
    found = [d for d in found if not any(d.network.subnet_of(c) for c in already if c.version == 4)]
    kept = netdiscover.within_budget(found, max(budget - used, 0), warnings)
    return configured + [str(d.network) for d in kept], kept


def run_scheduled(cfg, store, actor: str = "scan") -> tuple[ScanResult, list[Found], list[Found]]:
    """The daemon's scan job: scan per sources.ssl.scan, track new finds (if add: true).
    Returns (result, added, new_untracked)."""
    from zoneinfo import ZoneInfo

    from expiry.sources.sslcert import SslSource

    opts = cfg.get("sources.ssl.scan") or {}
    names = list(opts.get("names") or [])
    if opts.get("names_file"):
        names += read_names_file(opts["names_file"])
    domains = list(opts.get("domains") or [])
    ports = [int(p) for p in (opts.get("ports") or DEFAULT_PORTS)]
    warnings: list[str] = []
    networks, discovered = scan_networks(cfg, store, ports, warnings)
    result = scan(domains, names, networks, ports, bool(opts.get("certificate_logs", True)),
                  float(opts.get("timeout") or 3), match_all=match_all(opts, domains),
                  known_hosts=[t.host for t in SslSource(cfg, store).targets()])
    result.warnings = warnings + result.warnings
    result.networks = [str(d) for d in discovered]
    ids, addresses = tracked_state(SslSource(cfg, store).targets())
    new = [f for f in result.found if not is_tracked(f, ids, addresses)]
    added = track(store, new, actor, ZoneInfo(cfg.timezone), ids, addresses) if opts.get("add", True) else []
    return result, added, new
