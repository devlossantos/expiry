"""Put a name to an address the network scan found, so a row says which server it is, not just its IP.

A certificate found by sweeping an address range arrives with nothing but the IP that answered.
Reverse DNS alone often fails on office networks, which rarely have reverse zones. So several
clues are tried, the most trustworthy first:

  * forward DNS   - a host name this same scan resolved to that address (wiki.example.com -> 10.1.2.142)
  * reverse DNS   - the PTR record, when there is one
  * redirect      - the host name the web server redirects to: most apps send a bare-IP request to
                    their proper URL (Location: https://jira.example.com/), which names them exactly
  * certificate   - the certificate's own host name, when it names ONE host (never a wildcard, which
                    says nothing about which server it is on)

Separately, the page title (or the Server header when there is no title) says WHAT the device is
("Jira", "iLO 5", "Synology DiskStation"), which helps even when no name is found.
"""

from __future__ import annotations

import html
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from expiry.sources.sslcert import CertInfo, _legacy_context, _modern_context

MAX_READ = 64 * 1024
TITLE = re.compile(rb"<title[^>]*>(.*?)</title", re.IGNORECASE | re.DOTALL)
HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,62}\.)+[a-z0-9-]{1,63}$")


@dataclass
class Identity:
    name: str = ""    # host name for the address ("" = none found)
    via: str = ""     # how the name was found: dns | ptr | redirect | certificate
    title: str = ""   # what the device says it is: page title or Server header


def is_hostname(value: str) -> bool:
    value = (value or "").lower().rstrip(".")
    if not HOSTNAME.match(value):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


def _clean(text: str, limit: int = 60) -> str:
    text = " ".join(html.unescape(text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def parse_http(raw: bytes) -> tuple[str, str]:
    """(host name from the redirect, page title or Server header) from an HTTP response."""
    head, _, body = raw.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in head.decode("latin-1").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers.setdefault(key.strip().lower(), value.strip())
    host = urlsplit(headers.get("location", "")).hostname or ""
    host = host.lower().rstrip(".") if is_hostname(host) else ""
    m = TITLE.search(body)
    title = _clean(m.group(1).decode("utf-8", "replace")) if m else ""
    return host, title or _clean(headers.get("server", ""))


def http_hint(ip: str, port: int, timeout: float = 3.0) -> tuple[str, str]:
    """GET / over TLS without a host name, as the scan reached it. Never raises."""
    request = (f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: expiry-scan\r\nAccept: text/html\r\n"
               "Connection: close\r\n\r\n").encode()
    for make in (_modern_context, _legacy_context):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with make().wrap_socket(sock) as tls:
                    tls.sendall(request)
                    raw = b""
                    while len(raw) < MAX_READ:
                        chunk = tls.recv(8192)
                        if not chunk:
                            break
                        raw += chunk
                        if b"</title" in raw.lower():
                            break
            return parse_http(raw)
        except ssl.SSLError:
            continue  # an old device: try the legacy handshake once
        except (OSError, ValueError):
            break
    return "", ""


def certificate_host(info: CertInfo) -> str:
    """The host the certificate names, only when it names exactly one and no wildcard."""
    names = {n.lower().rstrip(".") for n in [info.common_name, *info.san] if n}
    if any(n.startswith("*.") for n in names):
        return ""
    hosts = sorted(n for n in names if is_hostname(n))
    return hosts[0] if len(hosts) == 1 else ""


def identify(ip: str, port: int, info: CertInfo, forward: dict[str, list[str]] | None = None,
             reverse=None, http=None, timeout: float = 3.0) -> Identity:
    """Best name and description for the server at ip:port. `forward` maps address -> host names
    resolved to it during this scan."""
    redirect, title = (http or http_hint)(ip, port, timeout)
    names = sorted(set((forward or {}).get(ip, [])), key=lambda n: (len(n), n))
    if names:
        covered = [n for n in names if _covers(info, n)]
        return Identity((covered or names)[0], "dns", title)
    ptr = reverse(ip) if reverse else ""
    if ptr and is_hostname(ptr):
        return Identity(ptr, "ptr", title)
    if redirect:
        return Identity(redirect, "redirect", title)
    host = certificate_host(info)
    if host:
        return Identity(host, "certificate", title)
    return Identity("", "", title)


def _covers(info: CertInfo, name: str) -> bool:
    for n in {x.lower().rstrip(".") for x in [info.common_name, *info.san] if x}:
        if n == name or (n.startswith("*.") and name.endswith(n[1:]) and name.count(".") == n.count(".")):
            return True
    return False
