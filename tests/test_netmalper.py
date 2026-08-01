import subprocess
import sys

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


def test_extract_nmap_xml():
    xml = '<?xml version="1.0"?><nmaprun><host/></nmaprun>'
    assert extract_nmap_xml(xml) == xml


def test_extract_nmap_xml_none():
    assert extract_nmap_xml("no xml here") is None


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
