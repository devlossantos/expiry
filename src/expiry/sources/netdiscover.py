"""Find the internal networks this server can reach, so the certificate scan needs no hand-typed list.

The scheduled scan (sources.ssl.scan) used to need every subnet written into the config, which in
practice meant nobody scanned anything. With discover_networks on (the default) the scan works the
networks out for itself, from four places:

  * routes      - the subnets of this machine's own interfaces and any routed private networks
                  (VPN tunnels to other sites included), read from /proc/net/route
  * gateway     - the subnet of the default gateway
  * DNS servers - the subnet of each private nameserver in /etc/resolv.conf: in an office network
                  the domain controllers that serve DNS sit with the other servers
  * known hosts - the subnet around every server already tracked or listed in sources.ssl.hosts:
                  servers cluster, so the neighbours of known ones are the likeliest unknown ones

Safety rules, all applied here rather than left to the caller:
  * only PRIVATE IPv4 space (10/8, 172.16/12, 192.168/16) is ever returned; public addresses,
    loopback, link-local and carrier-grade NAT (100.64/10) never are
  * a large interface network (a /16 LAN) is narrowed to this server's own /24, never scanned whole
  * container bridge networks (Docker's own 172.x ranges) are skipped: scanning them would only find
    other containers on the same host
  * sources.ssl.scan.exclude_networks removes anything you do not want touched
  * the caller trims the result to the scan's address budget, in the order above

IPv6 is not discovered: a single /64 has 2^64 addresses, so it cannot be swept. Track IPv6 hosts by
name or address instead.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

# Interfaces that never lead to servers worth scanning: loopback, container and VM bridges, overlays.
SKIP_INTERFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "cilium",
                           "kube", "vxlan", "weave", "podman", "lxc", "lxd")
CGNAT = ipaddress.ip_network("100.64.0.0/10")
SYSTEMD_RESOLV = "/run/systemd/resolve/resolv.conf"
PRIVATE_V4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


@dataclass
class Discovered:
    network: ipaddress.IPv4Network
    reasons: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.network} ({'; '.join(self.reasons)})"


def is_scannable(ip: ipaddress.IPv4Address | ipaddress.IPv4Network) -> bool:
    """Private IPv4 only. Deliberately narrower than ipaddress.is_private, which also covers
    documentation, benchmarking and other reserved ranges."""
    if isinstance(ip, ipaddress.IPv4Network):
        return any(ip.subnet_of(p) for p in PRIVATE_V4)
    return isinstance(ip, ipaddress.IPv4Address) and any(ip in p for p in PRIVATE_V4) and ip not in CGNAT


def _hex_ip(value: str) -> ipaddress.IPv4Address:
    """/proc/net/route stores addresses as little-endian hex."""
    return ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(value), "little"))


def read_routes(path: str = "/proc/net/route") -> list[tuple[str, ipaddress.IPv4Network | None,
                                                               ipaddress.IPv4Address | None]]:
    """(interface, network or None for the default route, gateway or None)."""
    try:
        lines = Path(path).read_text(encoding="ascii", errors="replace").splitlines()[1:]
    except OSError:
        return []
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest, gateway, mask = parts[0], parts[1], parts[2], parts[7]
        try:
            gw = _hex_ip(gateway)
            mask_ip = _hex_ip(mask)
            dest_ip = _hex_ip(dest)
        except ValueError:
            continue
        gw_out = gw if int(gw) else None
        if int(mask_ip) == 0:
            out.append((iface, None, gw_out))
        else:
            prefix = bin(int(mask_ip)).count("1")
            out.append((iface, ipaddress.IPv4Network(f"{dest_ip}/{prefix}", strict=False), gw_out))
    return out


def read_nameservers(path: str = "/etc/resolv.conf") -> list[ipaddress.IPv4Address]:
    out = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                ip = ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            if isinstance(ip, ipaddress.IPv4Address):
                out.append(ip)
    return out


def in_container() -> bool:
    return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")


def local_address_for(network: ipaddress.IPv4Network) -> ipaddress.IPv4Address | None:
    """This machine's own address on `network`, found by asking the kernel which source address it
    would use. A UDP connect sends no packet."""
    probe_ip = next(network.hosts(), None) or network.network_address
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((str(probe_ip), 9))
        addr = ipaddress.IPv4Address(sock.getsockname()[0])
    except OSError:
        return None
    finally:
        sock.close()
    return addr if addr in network else None


def _resolve_v4(host: str) -> list[ipaddress.IPv4Address]:
    try:
        ip = ipaddress.ip_address(host)
        return [ip] if isinstance(ip, ipaddress.IPv4Address) else []
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({ipaddress.IPv4Address(i[4][0]) for i in infos})


def discover(known_hosts: list[str] | None = None, prefix: int = 24, exclude: list[str] | None = None,
             route_file: str = "/proc/net/route", resolv_file: str = "/etc/resolv.conf",
             container: bool | None = None, local_address=None, resolver=None,
             warnings: list[str] | None = None) -> list[Discovered]:
    """Private networks worth scanning, most certain first. Each comes with the reasons it was chosen,
    so `expiry ssl networks` can show its working."""
    container = in_container() if container is None else container
    local_address = local_address or local_address_for
    resolver = resolver or _resolve_v4
    excluded = [ipaddress.ip_network(str(n), strict=False) for n in (exclude or [])]
    found: dict[ipaddress.IPv4Network, Discovered] = {}

    def add(net: ipaddress.IPv4Network, reason: str) -> None:
        if not is_scannable(net):
            return
        if any(net.overlaps(x) for x in excluded):
            return
        found.setdefault(net, Discovered(net)).reasons.append(reason)

    def around(ip: ipaddress.IPv4Address) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)

    routes = read_routes(route_file)
    # In a container on Docker's default bridge, the routes describe the bridge, not the office
    # network: the host's own docker0/br- interfaces are only visible with host networking.
    host_netns = any(iface.startswith(("docker", "br-")) for iface, _, _ in routes)
    use_routes = not container or host_netns
    if routes and not use_routes and warnings is not None:
        warnings.append("running in a container on a bridge network: this server's own subnets are not "
                        "visible, so discovery uses DNS servers and known hosts only (run the container "
                        "with network_mode: host to scan the server's own subnets too)")

    if use_routes:
        for iface, net, gw in routes:
            if iface.startswith(SKIP_INTERFACE_PREFIXES):
                continue
            if net is None:
                if gw is not None and is_scannable(gw):
                    add(around(gw), f"default gateway {gw} ({iface})")
                continue
            if not is_scannable(net):
                continue
            if net.prefixlen >= prefix:
                add(net, f"{'route via ' + str(gw) if gw else 'own subnet'} on {iface}")
                continue
            # a large network (a /16 LAN): never sweep it whole, take the slice this server is in
            own = local_address(net)
            if own is not None:
                add(around(own), f"own subnet on {iface} ({net} narrowed to the /{prefix} around {own})")
            elif warnings is not None:
                warnings.append(f"{net} on {iface} is larger than /{prefix} and this server has no address "
                                "in it, so it was skipped; list the parts you want in sources.ssl.scan.networks")

    servers = read_nameservers(resolv_file)
    if servers and all(ns.is_loopback for ns in servers):
        # systemd-resolved (Ubuntu) puts its local stub 127.0.0.53 here; the real servers are
        # in its own file, visible to a container only if /run/systemd/resolve is mounted
        servers = read_nameservers(SYSTEMD_RESOLV) or servers
    for ns in servers:
        if is_scannable(ns):
            add(around(ns), f"DNS server {ns}")

    for host in known_hosts or []:
        for ip in resolver(host):
            if is_scannable(ip):
                add(around(ip), f"near {host}")

    # a network inside a larger one already chosen adds nothing but its reasons
    ordered = list(found.values())
    out: list[Discovered] = []
    for d in sorted(ordered, key=lambda d: d.network.prefixlen):
        parent = next((o for o in out if d.network.subnet_of(o.network)), None)
        if parent:
            parent.reasons.extend(r for r in d.reasons if r not in parent.reasons)
        else:
            out.append(d)
    # most certain first: own subnets and routes, then gateway, DNS, known hosts (insertion order)
    rank = {d.network: i for i, d in enumerate(ordered)}
    out.sort(key=lambda d: rank.get(d.network, len(rank)))
    for d in out:
        d.reasons = list(dict.fromkeys(d.reasons))
    return out


def explain_empty(known_hosts: list[str] | None = None, route_file: str = "/proc/net/route",
                  resolv_file: str = "/etc/resolv.conf", container: bool | None = None) -> list[str]:
    """Why discover() found nothing, source by source, for `expiry ssl networks`."""
    container = in_container() if container is None else container
    routes = read_routes(route_file)
    nets = [str(n) for i, n, _ in routes if n is not None and not i.startswith(SKIP_INTERFACE_PREFIXES)]
    host_netns = any(i.startswith(("docker", "br-")) for i, _, _ in routes)
    out = []
    if container and not host_netns:
        out.append("routes: this container is on a bridge network, so the server's own subnets are not "
                   "visible (recreate it with --network host / network_mode: host)")
    else:
        out.append("routes: " + (", ".join(nets) + " (none of them private IPv4)" if nets else "none found"))
    servers = read_nameservers(resolv_file)
    if servers and all(s.is_loopback for s in servers):
        servers = read_nameservers(SYSTEMD_RESOLV) or servers
    shown = ", ".join(map(str, servers)) or "none"
    hint = (" (a local DNS cache; mount /run/systemd/resolve:/run/systemd/resolve:ro to see the real servers)"
            if servers and all(s.is_loopback for s in servers) else
            "" if any(is_scannable(s) for s in servers) else " (none private)")
    out.append(f"DNS servers: {shown}{hint}")
    out.append(f"tracked hosts: {len(known_hosts or [])}, none resolving to a private address"
               if known_hosts else "tracked hosts: none yet")
    return out


def within_budget(discovered: list[Discovered], max_addresses: int,
                  warnings: list[str] | None = None) -> list[Discovered]:
    """Keep networks, most certain first, while their addresses fit the budget."""
    kept, used = [], 0
    for d in discovered:
        size = d.network.num_addresses  # counted the way scan() counts its limit
        if used + size > max_addresses:
            if warnings is not None:
                warnings.append(f"{d.network} not scanned this time: over the per-scan limit "
                                f"({max_addresses} addresses); exclude networks you don't need")
            continue
        kept.append(d)
        used += size
    return kept
