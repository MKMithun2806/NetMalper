import socket
import subprocess
import sys

import netmalper.cli as cli
from netmalper.cli import (
    VERSION,
    extract_nmap_xml,
    parse_naabu_ports,
    parse_port_range,
    parse_rustscan_ports,
)


def test_version():
    assert VERSION == "8.0.0"


def test_parse_port_range():
    assert parse_port_range("1,2,4-6") == [1, 2, 4, 5, 6]
    assert parse_port_range("80-82") == [80, 81, 82]
    assert parse_port_range("443") == [443]


def test_parse_rustscan_ports():
    out = "Discovered open port 443/tcp on 1.2.3.4\nDiscovered open port 22/tcp on 1.2.3.4\n"
    assert parse_rustscan_ports(out) == [22, 443]


def test_parse_rustscan_ports_empty():
    assert parse_rustscan_ports("") == []


def test_parse_naabu_ports():
    out = '{"host":"1.2.3.4","port":80,"protocol":"tcp"}\n'
    assert parse_naabu_ports(out) == [80]


def test_parse_naabu_ports_silent_lines():
    out = "scanme.nmap.org:22\n10.0.0.1:443\n"
    assert parse_naabu_ports(out) == [22, 443]


def test_parse_naabu_ports_no_false_positive():
    assert parse_naabu_ports("host:10.0.0.1") == []
    assert parse_naabu_ports("no colon here") == []
    assert parse_naabu_ports("host:70000") == []


def test_extract_fqdns_bare_lines():
    assert cli._extract_fqdns("www.example.com", "example.com") == ["www.example.com"]
    assert cli._extract_fqdns("example.com", "example.com") == []


def test_extract_fqdns_relation_lines():
    line = "www.example.com (FQDN) --> A --> 1.2.3.4 (IPAddress)"
    assert cli._extract_fqdns(line, "example.com") == ["www.example.com"]
    assert cli._extract_fqdns(line, "other.com") == []


def test_extract_fqdns_ignores_junk():
    line = "--> (FQDN) --> 10.0.0.1 (IPAddress) -->"
    assert cli._extract_fqdns(line, "example.com") == []


def test_extract_fqdns_dedupes_and_sorts():
    line = "b.example.com --> a.example.com --> b.example.com"
    assert cli._extract_fqdns(line, "example.com") == ["a.example.com", "b.example.com"]


def test_extract_nmap_xml():
    xml = '<?xml version="1.0"?><nmaprun><host/></nmaprun>'
    assert extract_nmap_xml(xml) == xml


def test_extract_nmap_xml_none():
    assert extract_nmap_xml("no xml here") is None


def test_resolve_host_dedupes_and_sorts(monkeypatch):
    def fake_getaddrinfo(host, port):
        return [
            (2, 1, 6, "", ("1.2.3.4", 0)),
            (2, 1, 6, "", ("1.2.3.4", 0)),
            (2, 1, 6, "", ("5.6.7.8", 0)),
        ]

    monkeypatch.setattr(cli.socket, "getaddrinfo", fake_getaddrinfo)
    assert cli.resolve_host("example.com", timeout=1) == ["1.2.3.4", "5.6.7.8"]


def test_brute_subdomains_collects_live_names(monkeypatch):
    live = {"www.example.com", "api.example.com"}

    def fake_getaddrinfo(host, port):
        if host in live:
            return [(2, 1, 6, "", (host, 0))]
        raise socket.gaierror("no such name")

    monkeypatch.setattr(cli.socket, "getaddrinfo", fake_getaddrinfo)
    found = cli.brute_subdomains("example.com", ["www", "api", "nope"], timeout=1, threads=4)
    assert found == {"www.example.com", "api.example.com"}


def test_cli_version():
    result = subprocess.run(
        [sys.executable, "-m", "netmalper", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert VERSION in result.stdout


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "netmalper", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "target" in result.stdout

