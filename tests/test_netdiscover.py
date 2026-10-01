"""Network discovery for the scheduled certificate scan.

Every input is faked (route table, resolv.conf, DNS, this server's own address), so these tests
never touch the network of the machine running them.
"""

import ipaddress
from zoneinfo import ZoneInfo

from conftest import make_config
from test_sslscan import NOT_AFTER, wildcard_server  # noqa: F401 - pytest fixture

from expiry.sources import netdiscover, sslscan

HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"


def _hex(ip: str) -> str:
    return int(ipaddress.IPv4Address(ip)).to_bytes(4, "little").hex().upper()


def route(iface, dest, mask, gateway="0.0.0.0"):
    return f"{iface}\t{_hex(dest)}\t{_hex(gateway)}\t0003\t0\t0\t0\t{_hex(mask)}\t0\t0\t0\n"


def write(tmp_path, routes="", resolv=""):
    (tmp_path / "route").write_text(HEADER + routes)
    (tmp_path / "resolv.conf").write_text(resolv)
    return str(tmp_path / "route"), str(tmp_path / "resolv.conf")


def nets(found):
    return [str(d.network) for d in found]


def test_reads_the_route_table(tmp_path):
    r, _ = write(tmp_path, route("eth0", "0.0.0.0", "0.0.0.0", "192.168.10.1")
                 + route("eth0", "192.168.10.0", "255.255.255.0")
                 + route("tun0", "10.20.0.0", "255.255.255.0", "10.8.0.1"))
    assert netdiscover.read_routes(r) == [
        ("eth0", None, ipaddress.IPv4Address("192.168.10.1")),
        ("eth0", ipaddress.IPv4Network("192.168.10.0/24"), None),
        ("tun0", ipaddress.IPv4Network("10.20.0.0/24"), ipaddress.IPv4Address("10.8.0.1")),
    ]


def test_finds_own_subnet_vpn_routes_gateway_dns_and_known_hosts(tmp_path):
    r, rc = write(
        tmp_path,
        route("eth0", "0.0.0.0", "0.0.0.0", "192.168.10.1")
        + route("eth0", "192.168.10.0", "255.255.255.0")
        + route("tun0", "10.20.0.0", "255.255.255.0", "10.8.0.1")   # a VPN route to another site
        + route("docker0", "172.17.0.0", "255.255.0.0"),            # container bridge: never
        "nameserver 10.1.1.10\nnameserver 8.8.8.8\nnameserver 127.0.0.53\n",
    )
    found = netdiscover.discover(["erp.corp.test"], route_file=r, resolv_file=rc, container=False,
                                 resolver=lambda h: [ipaddress.IPv4Address("10.1.5.7")])
    assert nets(found) == ["192.168.10.0/24", "10.20.0.0/24", "10.1.1.0/24", "10.1.5.0/24"]
    why = {str(d.network): "; ".join(d.reasons) for d in found}
    assert "own subnet on eth0" in why["192.168.10.0/24"]
    assert "default gateway" in why["192.168.10.0/24"], "the gateway's /24 merges into the subnet it is in"
    assert "DNS server 10.1.1.10" in why["10.1.1.0/24"]
    assert "near erp.corp.test" in why["10.1.5.0/24"]


def test_only_private_ipv4_is_ever_returned(tmp_path):
    r, rc = write(tmp_path, route("eth0", "203.0.113.0", "255.255.255.0")
                  + route("eth1", "100.64.0.0", "255.192.0.0")       # carrier-grade NAT
                  + route("eth2", "169.254.0.0", "255.255.0.0"),     # link-local
                  "nameserver 1.1.1.1\n")
    found = netdiscover.discover(["public.example"], route_file=r, resolv_file=rc, container=False,
                                 resolver=lambda h: [ipaddress.IPv4Address("93.184.216.34")])
    assert found == []


def test_a_large_lan_is_narrowed_to_this_servers_slice(tmp_path):
    r, rc = write(tmp_path, route("eth0", "10.0.0.0", "255.255.0.0"))
    found = netdiscover.discover([], route_file=r, resolv_file=rc, container=False,
                                 local_address=lambda net: ipaddress.IPv4Address("10.0.42.9"))
    assert nets(found) == ["10.0.42.0/24"]
    assert "narrowed" in found[0].reasons[0]


def test_container_bridge_routes_are_ignored_but_dns_still_works(tmp_path):
    """On Docker's default bridge the route table describes the bridge, not the office."""
    r, rc = write(tmp_path, route("eth0", "0.0.0.0", "0.0.0.0", "172.17.0.1")
                  + route("eth0", "172.17.0.0", "255.255.0.0"), "nameserver 10.1.1.10\n")
    warnings = []
    found = netdiscover.discover([], route_file=r, resolv_file=rc, container=True, warnings=warnings)
    assert nets(found) == ["10.1.1.0/24"]
    assert "network_mode: host" in warnings[0]


def test_host_networking_in_a_container_uses_the_routes(tmp_path):
    r, rc = write(tmp_path, route("eth0", "192.168.10.0", "255.255.255.0")
                  + route("docker0", "172.17.0.0", "255.255.0.0"))
    found = netdiscover.discover([], route_file=r, resolv_file=rc, container=True)
    assert nets(found) == ["192.168.10.0/24"]


def test_excluded_networks_are_never_returned(tmp_path):
    r, rc = write(tmp_path, route("eth0", "192.168.10.0", "255.255.255.0"), "nameserver 10.1.1.10\n")
    found = netdiscover.discover([], exclude=["10.0.0.0/8"], route_file=r, resolv_file=rc, container=False)
    assert nets(found) == ["192.168.10.0/24"]


def test_budget_keeps_the_most_certain_networks(tmp_path):
    found = [netdiscover.Discovered(ipaddress.IPv4Network(f"10.0.{i}.0/24"), ["x"]) for i in range(5)]
    warnings = []
    kept = netdiscover.within_budget(found, 3 * 256, warnings)
    assert nets(kept) == ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
    assert len(warnings) == 2


# ---------------------------------------------------------------- the scan keeps every certificate


def test_with_no_domain_every_certificate_on_the_network_is_kept(wildcard_server):  # noqa: F811
    port = wildcard_server
    res = sslscan.scan([], networks=["127.0.0.1/32"], ports=[port], use_logs=False,
                       reverse=lambda ip: "printer-2.office.lan", match_all=True)
    assert [(f.host, f.name) for f in res.found] == [("127.0.0.1", "printer-2.office.lan")]
    # the old behaviour, with a domain the certificate does not belong to, still filters
    res = sslscan.scan(["other.test"], networks=["127.0.0.1/32"], ports=[port], use_logs=False,
                       resolver=lambda h: [], reverse=lambda ip: "")
    assert res.found == []


def test_match_policy():
    assert sslscan.match_all({"match": "auto"}, []) is True
    assert sslscan.match_all({"match": "auto"}, ["corp.test"]) is False
    assert sslscan.match_all({"match": "all"}, ["corp.test"]) is True
    assert sslscan.match_all({"match": "domains"}, ["corp.test"]) is False


def test_the_scheduled_scan_needs_nothing_typed_in(store, wildcard_server, monkeypatch):  # noqa: F811
    """The point of the feature: no domain, no network, and the weekly job still finds and tracks
    a device's certificate, named by its reverse-DNS name."""
    port = wildcard_server
    monkeypatch.setattr(netdiscover, "discover", lambda *a, **k: [
        netdiscover.Discovered(ipaddress.IPv4Network("127.0.0.1/32"), ["own subnet on eth0"])])
    monkeypatch.setattr(sslscan, "reverse_name", lambda ip: "ilo-db01.office.lan")
    cfg = make_config(sources__ssl__scan={"enabled": True, "discover_networks": True, "domains": [],
                                          "networks": [], "ports": [port], "certificate_logs": False,
                                          "add": True, "names": [], "match": "auto"})
    result, added, new = sslscan.run_scheduled(cfg, store)
    assert result.networks == ["127.0.0.1/32 (own subnet on eth0)"]
    assert [(f.host, f.port) for f in added] == [("127.0.0.1", port)]
    r = store.get_by_external_id(f"ssl:127.0.0.1:{port}")
    assert r.name == f"SSL ilo-db01.office.lan (127.0.0.1:{port})"
    assert r.expires_on == NOT_AFTER.astimezone(ZoneInfo("UTC")).date()
    # next week: nothing new
    assert sslscan.run_scheduled(cfg, store)[1] == []


def test_the_scan_is_on_by_default_and_discovers():
    from expiry.config import DEFAULTS
    scan = DEFAULTS["sources"]["ssl"]["scan"]
    assert scan["enabled"] is True and scan["discover_networks"] is True and scan["match"] == "auto"


def test_systemd_resolved_stub_is_looked_through(tmp_path, monkeypatch):
    """Ubuntu's /etc/resolv.conf says 127.0.0.53; the real DNS servers are in systemd's own file."""
    r, rc = write(tmp_path, "", "nameserver 127.0.0.53\n")
    real = tmp_path / "systemd-resolv.conf"
    real.write_text("nameserver 10.1.1.10\n")
    monkeypatch.setattr(netdiscover, "SYSTEMD_RESOLV", str(real))
    found = netdiscover.discover([], route_file=r, resolv_file=rc, container=False)
    assert nets(found) == ["10.1.1.0/24"]


def test_an_empty_result_says_why(tmp_path, monkeypatch):
    monkeypatch.setattr(netdiscover, "SYSTEMD_RESOLV", str(tmp_path / "missing"))
    r, rc = write(tmp_path, route("eth0", "172.17.0.0", "255.255.0.0"), "nameserver 127.0.0.53\n")
    why = netdiscover.explain_empty(["www.example.com"], route_file=r, resolv_file=rc, container=True)
    assert "bridge network" in why[0] and "--network host" in why[0]
    assert "127.0.0.53" in why[1] and "/run/systemd/resolve" in why[1]
    assert "none resolving to a private address" in why[2]
