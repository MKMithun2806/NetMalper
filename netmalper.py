#!/usr/bin/env python3
"""
netmalper.py — network recon mapper  v3.0.0

Subdomain enumeration (layered, merged):
  1. Amass  --passive  (OSINT, no active probing — default when amass found)
  2. Custom wordlist brute-force (always runs, --subdomains to override file)
  Both sets are merged and deduplicated.

Port discovery pipeline:
  1. Naabu  → fast full-range sweep → discovers open ports
  2. Nmap   → deep scan on naabu-discovered ports only (not guessed defaults)
  3. Socket → parallel TCP connect on same ports (fallback + confirmation)
  If naabu not found → falls back to default port list for nmap/socket.

Nmap flags (privilege-aware):
  root    →  -sS (SYN) + -O (OS fingerprint)
  non-root → -sT (TCP connect)
  always  →  -sV --script default

Usage:
  python netmalper.py <target> [options]

Options:
  --subdomains FILE      Extra subdomain wordlist (merged with built-in)
  --out FILE             Output JSON (default: <target>_graph.json)
  --timeout SEC          Per-probe timeout (default: 3)
  --threads N            Thread count (default: 30)
  --nmap-timing T        Nmap timing 1-5 (default: 4)
  --naabu-ports RANGE    Naabu port range (default: 1-65535)
  --naabu-rate N         Naabu packets/sec (default: 1000)
  --amass-timeout SEC    Amass timeout in seconds (default: 120)
  --no-amass             Skip amass passive enum
  --no-wordlist          Skip built-in + custom wordlist brute-force
  --no-naabu             Skip naabu, use default port list
  --no-nmap              Skip nmap
  --no-socket            Skip socket scanner
  --no-http              Skip HTTP probing
  --no-ports             Skip all port scanning
  --no-subs              Skip all subdomain enumeration
  --no-dns               Skip DNS chain resolution
  --open-viewer          Open viewer after scan
  --viewer FILE          Path to netmalper_viewer.html
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

VERSION = "3.0.0"

# ── colours ───────────────────────────────────────────────────────────────────
R  = "\033[0m";  B  = "\033[1m"
CY = "\033[96m"; GN = "\033[92m"; YL = "\033[93m"
RD = "\033[91m"; GY = "\033[90m"; MG = "\033[95m"
BL = "\033[94m"

def log(level, msg):
    ts  = datetime.now().strftime("%H:%M:%S")
    sym = {
        "info":   f"{CY}[*]{R}",
        "ok":     f"{GN}[+]{R}",
        "warn":   f"{YL}[!]{R}",
        "err":    f"{RD}[-]{R}",
        "nmap":   f"{MG}[N]{R}",
        "naabu":  f"{BL}[P]{R}",   # P for ports
        "amass":  f"{CY}[A]{R}",
        "sock":   f"{BL}[S]{R}",
        "merge":  f"{YL}[M]{R}",
        "dns":    f"{GY}[D]{R}",
        "sub":    f"{GN}[B]{R}",   # B for brute
    }
    print(f"{GY}{ts}{R} {sym.get(level,'[?]')} {msg}", flush=True)

def banner(target, has_nmap, has_naabu, has_amass, is_root):
    tick  = lambda b: f"{GN}✓{R}" if b else f"{RD}✗{R}"
    priv  = f"{GN}root{R}" if is_root else f"{YL}non-root{R}"
    print(f"""
{CY}╔══════════════════════════════════════════════════════╗
║  {B}netmalper{R}{CY}  v{VERSION}  —  recon graph mapper            ║
╚══════════════════════════════════════════════════════╝{R}
{GY}  target   : {B}{target}{R}
{GY}  nmap      : {tick(has_nmap)}  naabu : {tick(has_naabu)}  amass : {tick(has_amass)}
{GY}  privs     : {priv}
{GY}  time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}
""")

# ── tool detection ────────────────────────────────────────────────────────────
def find_tool(name: str) -> Optional[str]:
    return shutil.which(name)

def check_root() -> bool:
    try:    return os.geteuid() == 0
    except: return False

# ── graph ─────────────────────────────────────────────────────────────────────
class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def add_node(self, nid: str, label: str, ntype: str, data: dict = None) -> str:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "label": label, "type": ntype, "data": data or {}}
        else:
            existing = self.nodes[nid]["data"]
            for k, v in (data or {}).items():
                if v not in (None, "", [], {}):
                    existing[k] = v
        return nid

    def add_edge(self, src: str, dst: str, label: str = ""):
        for e in self.edges:
            if e["source"] == src and e["target"] == dst and e["label"] == label:
                return
        self.edges.append({"source": src, "target": dst, "label": label})

    def to_dict(self, meta: dict) -> dict:
        return {"meta": meta, "nodes": list(self.nodes.values()), "edges": self.edges}

# ── DNS ───────────────────────────────────────────────────────────────────────
def dns_chain(fqdn: str, g: Graph, parent_id: str, timeout: int = 3):
    current, prev_id, depth, seen = fqdn, parent_id, 0, set()
    while depth < 10:
        if current in seen: break
        seen.add(current); depth += 1
        cname_target = None
        try:
            r = subprocess.run(["dig", "+short", "CNAME", current],
                               capture_output=True, text=True, timeout=timeout)
            lines = [l.strip().rstrip(".") for l in r.stdout.strip().splitlines() if l.strip()]
            if lines: cname_target = lines[0]
        except Exception: pass

        if cname_target:
            nid = f"cname:{cname_target}"
            g.add_node(nid, cname_target, "cname", {"fqdn": cname_target})
            g.add_edge(prev_id, nid, "CNAME")
            log("dns", f"  CNAME {current} → {cname_target}")
            prev_id, current = nid, cname_target
        else:
            try:
                ips = socket.getaddrinfo(current, None)
                for ip in {r[4][0] for r in ips}:
                    nid = f"ip:{ip}"
                    try:    rdns, _, _ = socket.gethostbyaddr(ip)
                    except: rdns = ip
                    g.add_node(nid, ip, "ip", {
                        "ip": ip, "reverse_dns": rdns,
                        "is_private": _is_private(ip),
                    })
                    g.add_edge(prev_id, nid, "A")
                    log("dns", f"  A {current} → {ip} ({rdns})")
            except Exception as ex:
                log("warn", f"  DNS fail for {current}: {ex}")
            break

def _is_private(ip: str) -> bool:
    try:    return ipaddress.ip_address(ip).is_private
    except: return False

# ══════════════════════════════════════════════════════════════════════════════
#  SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

BUILTIN_SUBS = [
    "www","mail","smtp","pop","imap","ftp","sftp","ssh",
    "api","api2","api3","v1","v2","v3",
    "dev","dev2","development","staging","stage","stg",
    "test","testing","qa","uat","sandbox","demo",
    "admin","administrator","portal","dashboard","panel",
    "login","auth","sso","oauth","accounts",
    "cdn","static","assets","media","img","images","files",
    "blog","docs","help","support","wiki","kb",
    "shop","store","checkout","payment","payments",
    "app","web","mobile","m","wap",
    "internal","intranet","corp","vpn","remote",
    "git","gitlab","github","bitbucket","repo","code",
    "ci","cd","jenkins","travis","build",
    "db","database","mysql","postgres","redis","mongo",
    "grafana","kibana","prometheus","monitor","metrics",
    "k8s","kubernetes","docker","registry","harbor",
    "backup","bak","old","legacy",
    "ns","ns1","ns2","dns","dns1","dns2",
    "mx","mx1","mx2","webmail",
    "status","health","ping",
    "webhooks","webhook","hooks","callback",
    "push","pull","events",
    "beta","alpha","rc",
    "secure","ssl","tls",
    "office","teams","slack","chat",
    "crm","erp","hr",
    "analytics","track","pixel",
    "proxy","gateway","edge",
    "search","solr","elasticsearch","es",
]

# ── amass passive ─────────────────────────────────────────────────────────────
def run_amass(target: str, amass_bin: str, timeout: int) -> set[str]:
    """Run amass enum --passive and return set of discovered FQDNs."""
    log("amass", f"Running passive OSINT enum for {B}{target}{R}…")
    found: set[str] = set()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        out_file = tf.name

    cmd = [
        amass_bin, "enum",
        "--passive",
        "-d", target,
        "-o", out_file,
        "-timeout", str(timeout // 60 or 2),   # amass uses minutes
    ]
    log("amass", f"  cmd: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        log("warn", "amass timed out — using partial results")
    except Exception as e:
        log("err", f"amass error: {e}")
        os.unlink(out_file)
        return found

    if os.path.exists(out_file):
        with open(out_file) as f:
            for line in f:
                fqdn = line.strip().lower()
                if fqdn and fqdn.endswith(f".{target}") or fqdn == target:
                    # strip the root domain to get just the subdomain prefix
                    if fqdn != target:
                        found.add(fqdn)
        os.unlink(out_file)

    log("amass", f"  found {GN}{len(found)}{R} subdomains via passive OSINT")
    return found

# ── wordlist brute-force ──────────────────────────────────────────────────────
def brute_subdomains(target: str, wordlist: list[str],
                     timeout: int, threads: int) -> set[str]:
    """DNS brute-force against wordlist. Returns set of live FQDNs."""
    found: set[str] = set()

    def check(sub):
        fqdn = f"{sub}.{target}" if not sub.endswith(f".{target}") else sub
        try:
            socket.getaddrinfo(fqdn, None, timeout=timeout)
            return fqdn
        except Exception:
            return None

    log("sub", f"Wordlist brute-force: {len(wordlist)} candidates ({threads} threads)…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(check, wordlist):
            if result:
                found.add(result)

    log("sub", f"  found {GN}{len(found)}{R} subdomains via brute-force")
    return found

# ── merge + add to graph ──────────────────────────────────────────────────────
def enum_subdomains(target: str, g: Graph, root_id: str,
                    amass_bin: Optional[str], wordlist: list[str],
                    timeout: int, threads: int,
                    use_amass: bool, use_wordlist: bool,
                    amass_timeout: int) -> list[str]:

    all_fqdns: set[str] = set()

    # run amass + wordlist in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures = {}
        if use_amass and amass_bin:
            futures["amass"] = ex.submit(run_amass, target, amass_bin, amass_timeout)
        if use_wordlist and wordlist:
            futures["brute"] = ex.submit(brute_subdomains, target, wordlist, timeout, threads)

        for key, fut in futures.items():
            try:
                all_fqdns |= fut.result()
            except Exception as e:
                log("warn", f"{key} failed: {e}")

    if not all_fqdns:
        log("warn", "No subdomains discovered")
        return []

    log("merge", f"Total unique subdomains (amass + brute merged): {GN}{len(all_fqdns)}{R}")

    # add to graph + DNS chain each
    confirmed = []
    for fqdn in sorted(all_fqdns):
        try:
            ips_raw = socket.getaddrinfo(fqdn, None)
            ips     = list({r[4][0] for r in ips_raw})
        except Exception:
            continue  # couldn't resolve — skip

        nid = f"sub:{fqdn}"
        g.add_node(nid, fqdn, "subdomain", {"fqdn": fqdn, "ips": ips})
        g.add_edge(root_id, nid, "subdomain")
        log("ok", f"  {fqdn} → {', '.join(ips)}")
        confirmed.append(fqdn)
        dns_chain(fqdn, g, nid, timeout)

    return confirmed

# ══════════════════════════════════════════════════════════════════════════════
#  PORT DISCOVERY — NAABU
# ══════════════════════════════════════════════════════════════════════════════

def run_naabu(host: str, naabu_bin: str, port_range: str,
              rate: int, timeout: int) -> list[int]:
    """
    Run naabu for fast port discovery.
    Returns sorted list of open port numbers.
    """
    log("naabu", f"Sweeping {B}{host}{R} ports {port_range} @ {rate} pps…")
    open_ports: list[int] = []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        out_file = tf.name

    cmd = [
        naabu_bin,
        "-host",    host,
        "-p",       port_range,
        "-rate",    str(rate),
        "-silent",
        "-o",       out_file,
        "-timeout", str(timeout * 1000),   # naabu uses ms
        "-retries", "2",
    ]
    log("naabu", f"  cmd: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 3 + 60)
    except subprocess.TimeoutExpired:
        log("warn", f"naabu timed out on {host} — using partial results")
    except Exception as e:
        log("err", f"naabu error: {e}")
        if os.path.exists(out_file): os.unlink(out_file)
        return []

    # naabu output format: host:port  (one per line)
    if os.path.exists(out_file):
        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                # handle both  "host:port"  and  plain  "port"
                parts = line.rsplit(":", 1)
                try:
                    open_ports.append(int(parts[-1]))
                except ValueError:
                    pass
        os.unlink(out_file)

    open_ports = sorted(set(open_ports))
    log("naabu", f"  {GN}{len(open_ports)}{R} open ports: {GY}{open_ports[:20]}"
                 f"{'…' if len(open_ports)>20 else ''}{R}")
    return open_ports

# ══════════════════════════════════════════════════════════════════════════════
#  NMAP
# ══════════════════════════════════════════════════════════════════════════════

SERVICE_MAP = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP/TLS",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",2375:"Docker",2376:"Docker-TLS",
    3000:"Dev-HTTP",3306:"MySQL",3389:"RDP",4848:"GlassFish",
    5432:"PostgreSQL",5672:"RabbitMQ",5900:"VNC",6379:"Redis",
    7474:"Neo4j",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9000:"SonarQube",9200:"Elasticsearch",9300:"ES-Internal",
    11211:"Memcached",15672:"RabbitMQ-Mgmt",27017:"MongoDB",
    27018:"MongoDB-Alt",50070:"Hadoop",
}

DEFAULT_PORTS = [
    21,22,23,25,53,80,110,143,443,445,
    993,995,3306,3389,5432,6379,
    8080,8443,8888,9200,27017,
]

def parse_port_range(s: str) -> list[int]:
    ports = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def build_nmap_cmd(nmap_bin: str, host: str, ports: list[int],
                   is_root: bool, timing: int) -> list[str]:
    cmd = [nmap_bin]
    if is_root:
        cmd += ["-sS", "-O"]
    else:
        cmd += ["-sT"]
    cmd += [
        "-sV", "--version-intensity", "5",
        "--script", "default",
        f"-T{timing}",
        "-p", ",".join(map(str, ports)),
        "--open",
        "-oX", "-",
        "--host-timeout", "120s",
        host,
    ]
    return cmd

def run_nmap(nmap_bin: str, host: str, ports: list[int],
             is_root: bool, timing: int) -> Optional[str]:
    cmd = build_nmap_cmd(nmap_bin, host, ports, is_root, timing)
    log("nmap", f"Scanning {B}{host}{R} on {len(ports)} port(s)…")
    log("nmap", f"  cmd: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.stdout.strip() else None
    except subprocess.TimeoutExpired:
        log("warn", f"nmap timed out on {host}")
        return None
    except Exception as e:
        log("err", f"nmap failed: {e}")
        return None

def parse_nmap_xml(xml_str: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        log("warn", f"nmap XML parse error: {e}")
        return []

    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is not None and state_el.get("state") != "up":
            continue
        addr = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                addr = addr_el.get("addr", "")
                break
        if not addr: continue

        host_data = {"host": addr, "state": "up", "os_matches": [], "ports": []}

        os_el = host_el.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch"):
                host_data["os_matches"].append({
                    "name":     m.get("name",""),
                    "accuracy": m.get("accuracy",""),
                })

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                s2 = port_el.find("state")
                if s2 is None or s2.get("state") != "open": continue

                portnum  = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol","tcp")
                svc_el   = port_el.find("service")
                service  = product = version = extrainfo = ""
                cpe_list: list[str] = []

                if svc_el is not None:
                    service   = svc_el.get("name","")
                    product   = svc_el.get("product","")
                    version   = svc_el.get("version","")
                    extrainfo = svc_el.get("extrainfo","")
                    for cpe_el in svc_el.findall("cpe"):
                        cpe_list.append(cpe_el.text or "")

                scripts = []
                for script_el in port_el.findall("script"):
                    sid    = script_el.get("id","")
                    output = script_el.get("output","")
                    tables = []
                    for tbl in script_el.findall(".//elem"):
                        k2, v2 = tbl.get("key",""), tbl.text or ""
                        if k2 and v2: tables.append(f"{k2}: {v2}")
                    if tables: output = output + "\n" + "\n".join(tables[:8])
                    scripts.append({"id": sid, "output": output.strip()[:400]})

                host_data["ports"].append({
                    "port":      portnum,
                    "protocol":  protocol,
                    "state":     "open",
                    "service":   service,
                    "product":   product,
                    "version":   version,
                    "extrainfo": extrainfo,
                    "cpe":       cpe_list,
                    "scripts":   scripts,
                })

        hosts.append(host_data)
    return hosts

def inject_nmap(host_results: list[dict], host: str, g: Graph, parent_id: str):
    for hr in host_results:
        ip     = hr["host"]
        ip_nid = f"ip:{ip}"

        if ip_nid not in g.nodes:
            try:    rdns, _, _ = socket.gethostbyaddr(ip)
            except: rdns = ip
            g.add_node(ip_nid, ip, "ip", {
                "ip": ip, "reverse_dns": rdns,
                "is_private": _is_private(ip), "source": "nmap",
            })
            g.add_edge(parent_id, ip_nid, "A")

        for osm in hr["os_matches"][:2]:
            if not osm["name"]: continue
            osnid = f"os:{ip}:{osm['name'][:40]}"
            g.add_node(osnid, osm["name"][:30], "os_guess", {
                "os_name": osm["name"], "accuracy": osm["accuracy"], "host": ip,
            })
            g.add_edge(ip_nid, osnid, f"OS {osm['accuracy']}%")
            log("nmap", f"  OS guess: {osm['name']} ({osm['accuracy']}%)")

        for p in hr["ports"]:
            portnum     = p["port"]
            svc_name    = p["service"] or SERVICE_MAP.get(portnum, "unknown")
            version_str = " ".join(filter(None, [p["product"], p["version"], p["extrainfo"]])).strip()
            port_nid    = f"port:{ip}:{portnum}"

            g.add_node(port_nid, f":{portnum}", "port", {
                "port": portnum, "service": svc_name,
                "product": p["product"], "version": p["version"],
                "version_str": version_str, "protocol": p["protocol"],
                "cpe": p["cpe"], "host": ip, "source": "nmap",
            })
            g.add_edge(ip_nid, port_nid, f"port/{svc_name}")

            vstr = f"{GN}{portnum}/open{R}  {YL}{svc_name}{R}"
            if version_str: vstr += f"  {GY}{version_str}{R}"
            log("nmap", f"  {vstr}")

            boring = {"ssl-date","ssh-hostkey","http-server-header"}
            for script in p["scripts"]:
                if not script["output"] or script["id"] in boring: continue
                snid = f"nse:{ip}:{portnum}:{script['id']}"
                g.add_node(snid, script["id"], "nse_finding", {
                    "script_id": script["id"], "output": script["output"],
                    "port": portnum, "host": ip,
                })
                g.add_edge(port_nid, snid, "NSE")
                log("nmap", f"  NSE [{script['id']}] {script['output'].splitlines()[0][:50]}")

# ══════════════════════════════════════════════════════════════════════════════
#  SOCKET SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def socket_scan(host: str, ports: list[int], g: Graph, parent_id: str,
                timeout: int, threads: int) -> list[int]:
    open_ports: list[int] = []

    def probe(port):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port, True
        except: return port, False

    log("sock", f"Socket scan {B}{host}{R} ({len(ports)} ports)…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                svc = SERVICE_MAP.get(port, "unknown")
                nid = f"port:{host}:{port}"
                if nid not in g.nodes:
                    g.add_node(nid, f":{port}", "port", {
                        "port": port, "service": svc,
                        "host": host, "source": "socket",
                    })
                    g.add_edge(parent_id, nid, f"port/{svc}")
                    log("sock", f"  {host}:{port} open ({svc})")
                else:
                    g.nodes[nid]["data"]["socket_confirmed"] = True
                open_ports.append(port)

    return sorted(set(open_ports))

# ══════════════════════════════════════════════════════════════════════════════
#  SCAN HOST  — naabu → nmap + socket (merged)
# ══════════════════════════════════════════════════════════════════════════════

def scan_host(host: str, fallback_ports: list[int], g: Graph, parent_id: str,
              timeout: int, threads: int,
              nmap_bin: Optional[str], naabu_bin: Optional[str],
              is_root: bool, use_nmap: bool, use_socket: bool,
              use_naabu: bool, timing: int,
              naabu_range: str, naabu_rate: int) -> list[int]:

    # ── step 1: naabu port discovery ─────────────────────────────────────────
    ports_to_scan: list[int] = fallback_ports
    naabu_ports:   list[int] = []

    if use_naabu and naabu_bin:
        naabu_ports = run_naabu(host, naabu_bin, naabu_range, naabu_rate, timeout * 10)
        if naabu_ports:
            ports_to_scan = naabu_ports
            log("merge", f"  naabu discovered {GN}{len(ports_to_scan)}{R} ports — "
                         f"feeding into nmap + socket")
        else:
            log("warn", f"  naabu found nothing on {host} — falling back to default ports")
    else:
        if not use_naabu:
            log("info", f"  naabu skipped — using {len(fallback_ports)} default ports")
        else:
            log("warn", f"  naabu not found — using {len(fallback_ports)} default ports")

    # ── step 2: nmap + socket in parallel on discovered ports ────────────────
    nmap_future   = None
    socket_future = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        if use_nmap and nmap_bin and ports_to_scan:
            nmap_future = ex.submit(run_nmap, nmap_bin, host,
                                    ports_to_scan, is_root, timing)
        if use_socket and ports_to_scan:
            socket_future = ex.submit(socket_scan, host, ports_to_scan,
                                      g, parent_id, timeout, threads)

        socket_ports: list[int] = socket_future.result() if socket_future else []
        nmap_xml:     Optional[str] = nmap_future.result() if nmap_future else None

    # inject nmap enrichment
    nmap_ports: list[int] = []
    if nmap_xml:
        host_results = parse_nmap_xml(nmap_xml)
        if host_results:
            inject_nmap(host_results, host, g, parent_id)
            for hr in host_results:
                nmap_ports += [p["port"] for p in hr["ports"]]
        else:
            log("warn", f"nmap returned no hosts for {host}")

    # merge
    all_open = sorted(set(socket_ports + nmap_ports))

    if nmap_xml or socket_ports:
        only_sock = set(socket_ports) - set(nmap_ports)
        only_nmap = set(nmap_ports)   - set(socket_ports)
        both      = set(socket_ports) & set(nmap_ports)
        sources   = []
        if naabu_ports:    sources.append(f"naabu={len(naabu_ports)}")
        if nmap_ports:     sources.append(f"nmap={len(nmap_ports)}")
        if socket_ports:   sources.append(f"socket={len(socket_ports)}")
        if both:           sources.append(f"confirmed={len(both)}")
        log("merge", f"  open={len(all_open)}  " + "  ".join(sources))

    return all_open

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP PROBING
# ══════════════════════════════════════════════════════════════════════════════

PROBE_PATHS = [
    "/","/healthz","/health","/ping","/status",
    "/robots.txt","/sitemap.xml","/.well-known/security.txt",
    "/api","/api/v1","/api/v2",
    "/metrics","/prometheus","/actuator","/actuator/health",
    "/debug/pprof/","/debug/vars","/debug/requests","/debug/events",
    "/.env","/config.json","/app.json",
    "/admin","/admin/","/dashboard",
    "/swagger","/swagger-ui","/swagger-ui.html",
    "/openapi.json","/api-docs",
    "/version","/info","/build",
    "/server-status","/server-info",
    "/.git/HEAD","/.git/config",
    "/wp-login.php","/wp-admin",
    "/phpmyadmin","/adminer",
]

def probe_http(host: str, g: Graph, parent_id: str,
               timeout: int, threads: int, open_ports: list[int]):
    schemes = []
    if 443 in open_ports or 8443 in open_ports:
        schemes.append(("https", 443 if 443 in open_ports else 8443))
    if 80 in open_ports or 8080 in open_ports:
        schemes.append(("http", 80 if 80 in open_ports else 8080))
    if not schemes:
        schemes = [("https", 443), ("http", 80)]

    targets = [(s, p, path) for s, p in schemes for path in PROBE_PATHS]

    def check(scheme, port, path):
        url = (f"{scheme}://{host}:{port}{path}"
               if port not in (80, 443) else f"{scheme}://{host}{path}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netmalper/3.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return url, resp.status, \
                       resp.headers.get("Content-Type",""), \
                       resp.headers.get("Server",""), \
                       resp.headers.get("Content-Length","?")
        except urllib.error.HTTPError as e:
            return url, e.code, "", "", ""
        except: return url, None, "", "", ""

    log("info", f"HTTP probing {len(targets)} paths on {host}…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for url, code, ctype, server, length in ex.map(lambda t: check(*t), targets):
            if code in (200, 201, 301, 302, 401, 403):
                clr = GN if code == 200 else (YL if code in (301,302) else RD)
                log("ok", f"  {clr}{code}{R} {url}  {GY}{server}{R}")
                path = urllib.parse.urlparse(url).path
                nid  = f"endpoint:{url}"
                g.add_node(nid, path or "/", "endpoint", {
                    "url": url, "status": code,
                    "content_type": ctype, "server": server,
                    "content_length": length,
                    "interesting": code == 200,
                })
                g.add_edge(parent_id, nid, str(code))

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="netmalper v3 — amass + naabu + nmap recon graph mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("target")
    ap.add_argument("--subdomains",     default=None,
                    help="Extra wordlist file — merged with built-in list")
    ap.add_argument("--out",            default=None)
    ap.add_argument("--timeout",        type=int, default=3)
    ap.add_argument("--threads",        type=int, default=30)
    ap.add_argument("--nmap-timing",    type=int, default=4, choices=range(1,6))
    ap.add_argument("--naabu-ports",    default="1-65535",
                    help="Naabu port range (default: full sweep 1-65535)")
    ap.add_argument("--naabu-rate",     type=int, default=1000)
    ap.add_argument("--amass-timeout",  type=int, default=120)
    ap.add_argument("--no-amass",       action="store_true")
    ap.add_argument("--no-wordlist",    action="store_true")
    ap.add_argument("--no-naabu",       action="store_true")
    ap.add_argument("--no-nmap",        action="store_true")
    ap.add_argument("--no-socket",      action="store_true")
    ap.add_argument("--no-http",        action="store_true")
    ap.add_argument("--no-ports",       action="store_true")
    ap.add_argument("--no-subs",        action="store_true")
    ap.add_argument("--no-dns",         action="store_true")
    ap.add_argument("--open-viewer",    action="store_true")
    ap.add_argument("--viewer",         default="netmalper_viewer.html")
    args = ap.parse_args()

    # ── sanitize target ───────────────────────────────────────────────────────
    target = args.target.lower().strip()
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0].split('?')[0].rstrip('.')
    safe_name = re.sub(r'[^\w.\-]', '_', target)
    out_path  = args.out or f"{safe_name}_graph.json"

    # ── detect tools ──────────────────────────────────────────────────────────
    is_root   = check_root()
    nmap_bin  = find_tool("nmap")  if not args.no_nmap   else None
    naabu_bin = find_tool("naabu") if not args.no_naabu  else None
    amass_bin = find_tool("amass") if not args.no_amass  else None

    use_nmap    = bool(nmap_bin)
    use_naabu   = bool(naabu_bin) and not args.no_naabu
    use_amass   = bool(amass_bin) and not args.no_amass
    use_socket  = not args.no_socket
    use_wordlist= not args.no_wordlist

    banner(target, use_nmap, use_naabu, use_amass, is_root)

    if use_nmap and is_root:
        log("info", f"{GN}SYN scan + OS fingerprinting enabled (root){R}")
    elif use_nmap:
        log("warn", "Non-root: using -sT (TCP connect), no OS fingerprint")

    if not naabu_bin and not args.no_naabu:
        log("warn", "naabu not found — using default port list for nmap/socket")
        log("warn", "  install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")

    if not amass_bin and not args.no_amass:
        log("warn", "amass not found — wordlist brute-force only")
        log("warn", "  install: go install -v github.com/owasp-amass/amass/v4/...@master")

    # ── build wordlist ────────────────────────────────────────────────────────
    wordlist = list(BUILTIN_SUBS)
    if args.subdomains:
        try:
            with open(args.subdomains) as f:
                extra = [l.strip() for l in f if l.strip()]
            # if file contains full FQDNs like sub.example.com, strip to prefix
            cleaned = []
            for w in extra:
                w = w.lower()
                if w.endswith(f".{target}"):
                    w = w[: -(len(target) + 1)]
                cleaned.append(w)
            # merge, deduplicate, preserve order
            combined = list(dict.fromkeys(wordlist + cleaned))
            log("info", f"Wordlist: {len(wordlist)} built-in + {len(cleaned)} custom "
                        f"= {len(combined)} total")
            wordlist = combined
        except FileNotFoundError:
            log("warn", f"Wordlist file not found: {args.subdomains} — using built-in only")
    else:
        log("info", f"Wordlist: {len(wordlist)} built-in entries (use --subdomains to extend)")

    t0 = time.time()
    g  = Graph()

    root_id = f"root:{target}"
    g.add_node(root_id, target, "root", {"fqdn": target})

    # ── 1. DNS chain ──────────────────────────────────────────────────────────
    if not args.no_dns:
        log("info", f"{'─'*50}")
        log("info", "DNS chain resolution…")
        dns_chain(target, g, root_id, args.timeout)

    # ── 2. Subdomain enumeration (amass passive + wordlist, parallel) ─────────
    found_subs: list[str] = []
    if not args.no_subs:
        log("info", f"{'─'*50}")
        log("info", f"Subdomain enumeration  "
                    f"[amass={'passive' if use_amass else 'skip'}  "
                    f"wordlist={'yes' if use_wordlist else 'skip'}]")
        found_subs = enum_subdomains(
            target, g, root_id,
            amass_bin, wordlist,
            args.timeout, args.threads,
            use_amass, use_wordlist,
            args.amass_timeout,
        )

    # ── 3. Port scanning: naabu → nmap + socket ───────────────────────────────
    fallback_ports = DEFAULT_PORTS
    scan_targets   = [target]
    scan_targets  += [n["data"]["ip"] for n in g.nodes.values() if n["type"] == "ip"]
    scan_targets   = list(dict.fromkeys(scan_targets))

    all_open: dict[str, list[int]] = {}
    if not args.no_ports:
        for st in scan_targets:
            parent = (f"root:{target}" if st == target
                      else f"ip:{st}"   if f"ip:{st}" in g.nodes
                      else root_id)
            log("info", f"{'─'*50}")
            log("info", f"Scanning {B}{st}{R}  "
                        f"[naabu→{'nmap+socket' if use_nmap else 'socket'}]")
            open_p = scan_host(
                st, fallback_ports, g, parent,
                args.timeout, args.threads,
                nmap_bin, naabu_bin,
                is_root, use_nmap, use_socket,
                use_naabu, args.nmap_timing,
                args.naabu_ports, args.naabu_rate,
            )
            all_open[st] = open_p

    # ── 4. HTTP probing ───────────────────────────────────────────────────────
    if not args.no_http:
        log("info", f"{'─'*50}")
        log("info", "HTTP endpoint probing…")
        for ht in [target] + found_subs:
            op     = all_open.get(ht, [])
            parent = f"root:{target}" if ht == target else f"sub:{ht}"
            probe_http(ht, g, parent, args.timeout, args.threads, op)

    # ── write output ──────────────────────────────────────────────────────────
    duration = round(time.time() - t0, 2)
    meta = {
        "target":       target,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "duration_s":   duration,
        "version":      VERSION,
        "nmap_used":    use_nmap,
        "naabu_used":   use_naabu,
        "amass_used":   use_amass,
        "root_scan":    is_root,
        "node_count":   len(g.nodes),
        "edge_count":   len(g.edges),
    }
    data = g.to_dict(meta)
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"""
{CY}{'─'*54}
  {GN}Scan complete{R}{CY} in {B}{duration}s{R}
  {GN}Nodes      :{R} {len(g.nodes)}
  {GN}Edges      :{R} {len(g.edges)}
  {GN}Subdomains :{R} {len(found_subs)}
  {GN}amass      :{R} {GN+'passive ✓'+R if use_amass else GY+'skipped'+R}
  {GN}naabu      :{R} {GN+'✓'+R if use_naabu else GY+'skipped (default ports)'+R}
  {GN}nmap       :{R} {GN+'✓'+R if use_nmap else GY+'skipped'+R}
  {GN}root scan  :{R} {GN+'SYN+OS'+R if is_root else YL+'TCP connect'+R}
  {GN}output     :{R} {out_path}
{CY}{'─'*54}{R}
""")

    if args.open_viewer and os.path.exists(args.viewer):
        import webbrowser
        webbrowser.open(
            f"file://{os.path.abspath(args.viewer)}"
            f"?graph={urllib.parse.quote(os.path.abspath(out_path))}"
        )

    return out_path

if __name__ == "__main__":
    main()
