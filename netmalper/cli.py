#!/usr/bin/env python3
"""
netmalper.py — network recon mapper  v8.0.0

Subdomain enumeration (layered, merged):
  1. Amass  --active by default, --passive in stealth mode
  2. Custom wordlist brute-force (always runs, --subdomains to override file)
  Both sets are merged and deduplicated.

Port discovery pipeline:
  1. RustScan → fast port discovery + Nmap service/version analysis
  2. Naabu   → stealth port discovery + Nmap deep scanning
  3. Socket / full Nmap → fallback scans that run only after the primary scanner fails
  If the primary scanner is not available → falls back to socket/full-Nmap scanning.

RustScan mode:
  Uses Nmap XML when available; greppable output is the fallback mode.

Usage:
  python netmalper.py <target> [options]

Options:
  --subdomains FILE      Extra subdomain wordlist (merged with built-in)
  --out FILE             Output JSON (default: <target>_graph.json)
  --timeout SEC          Per-probe timeout (default: 3)
  --threads N            Thread count (default: 30)
  --amass-timeout SEC    Amass active-mode timeout in seconds (default: 1800)
  --stealth              Use Naabu + Nmap deep scanning and passive Amass
  --no-amass             Skip Amass enumeration
  --no-wordlist          Skip built-in + custom wordlist brute-force
  --no-rustscan          Skip RustScan and use the socket scanner only
  --rustscan-greppable   Parse RustScan's greppable output instead of Nmap XML
  --rustscan-batch-size N  RustScan batch size (default: 4500)
  --rustscan-timeout MS  RustScan timeout in milliseconds (default: 1500)
  --rustscan-process-timeout SEC  Total port-scan process budget across retries (default: 1800, max: 1800)
  --rustscan-retries N   RustScan retry attempts (default: 3)
  --rustscan-min-batch-size N  Minimum RustScan batch size on retries (default: 128)
  --rustscan-nofile-soft N  Soft RLIMIT_NOFILE floor to try to raise to (default: 8192)
  --no-socket            Skip socket scanner
  --no-http              Skip HTTP probing
  --no-ports             Skip all port scanning
  --no-subs              Skip all subdomain enumeration
  --no-dns               Skip DNS chain resolution
  --open-viewer          Open viewer after scan
  --viewer FILE          Path to netmalper_visualizer.html
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
from pathlib import Path
from typing import Optional

try:
    import resource
except ImportError:  # pragma: no cover - non-Unix platforms
    resource = None

VERSION = "8.0.0"
RUSTSCAN_PROCESS_TIMEOUT_MAX = 1800

def resolve_viewer(viewer_arg: str) -> Optional[str]:
    """Locate the HTML viewer shipped with the package, deb, or repo."""
    candidates = []
    if viewer_arg and viewer_arg != "netmalper_visualizer.html":
        candidates.append(Path(viewer_arg))
    candidates += [
        Path("/usr/share/netmalper/netmalper_visualizer.html"),
        Path(sys.prefix) / "share/netmalper/netmalper_visualizer.html",
    ]
    try:
        import importlib.resources as ilr
        candidates.append(Path(str(ilr.files("visualizer").joinpath("netmalper_visualizer.html"))))
    except Exception:
        pass
    candidates.append(Path("netmalper_visualizer.html"))
    for c in candidates:
        try:
            if c.is_file():
                return str(c)
        except Exception:
            pass
    return None

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
        "rs":     f"{MG}[RS]{R}",
        "naabu":  f"{MG}[NB]{R}",
        "nmap":   f"{BL}[NM]{R}",
        "amass":  f"{CY}[A]{R}",
        "sock":   f"{BL}[S]{R}",
        "merge":  f"{YL}[M]{R}",
        "dns":    f"{GY}[D]{R}",
        "sub":    f"{GN}[B]{R}",   # B for brute
    }
    print(f"{GY}{ts}{R} {sym.get(level,'[?]')} {msg}", flush=True)

def banner(target, has_rustscan, has_naabu, has_amass, is_root, stealth):
    tick  = lambda b: f"{GN}✓{R}" if b else f"{RD}✗{R}"
    priv  = f"{GN}root{R}" if is_root else f"{YL}non-root{R}"
    mode  = f"{MG}stealth{R}" if stealth else f"{CY}standard{R}"
    print(f"""
{CY}╔══════════════════════════════════════════════════════╗
║  {B}netmalper{R}{CY}  v{VERSION}  —  recon graph mapper            ║
╚══════════════════════════════════════════════════════╝{R}
{GY}  target   : {B}{target}{R}
{GY}  rustscan : {tick(has_rustscan)}  naabu : {tick(has_naabu)}  amass : {tick(has_amass)}
{GY}  mode     : {mode}
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

# ── amass enumeration ─────────────────────────────────────────────────────────
def run_amass(target: str, amass_bin: str, timeout: int, passive: bool) -> set[str]:
    """Run amass enum in passive or active mode and return discovered FQDNs."""
    mode = "passive" if passive else "active"
    log("amass", f"Running {mode} OSINT enum for {B}{target}{R}…")
    found: set[str] = set()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        out_file = tf.name

    cmd = [amass_bin, "enum"]
    cmd.append("--passive" if passive else "--active")
    cmd += [
        "-d", target,
        "-o", out_file,
        "-timeout", str(max(1, timeout // 60)),   # amass uses minutes
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

    log("amass", f"  found {GN}{len(found)}{R} subdomains via {mode} OSINT")
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
                    amass_timeout: int, amass_passive: bool) -> list[str]:

    all_fqdns: set[str] = set()

    # run amass + wordlist in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures = {}
        if use_amass and amass_bin:
            futures["amass"] = ex.submit(run_amass, target, amass_bin, amass_timeout, amass_passive)
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
#  PORT DISCOVERY — RUSTSCAN
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


def ensure_nofile_limit(min_soft: int = 8192) -> bool:
    """
    Best-effort raise of RLIMIT_NOFILE for RustScan inside containers.
    Returns True if the limit was adjusted, False otherwise.
    """
    if resource is None:
        return False
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(max(soft, min_soft), hard)
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            log("warn", f"raised RLIMIT_NOFILE from {soft} to {target} for RustScan")
            return True
    except Exception as e:
        log("warn", f"could not adjust RLIMIT_NOFILE: {e}")
    return False


def rustscan_retry_reason(output: str, returncode: int) -> Optional[str]:
    text = (output or "").lower()
    if "too many open files" in text or "ulimit" in text or "emfile" in text:
        return "ulimit"
    if "file descriptor" in text or "os error 24" in text:
        return "nofile"
    if "resource temporarily unavailable" in text:
        return "resources"
    if "blocked" in text or "rate limit" in text or "too fast" in text:
        return "rate"
    if returncode != 0 and not text:
        return "exit"
    return None


def rustscan_backoff(batch_size: int, timeout_ms: int, attempt: int,
                     min_batch_size: int) -> tuple[int, int]:
    """
    Gradually slow RustScan down on retries.
    """
    if attempt <= 0:
        return batch_size, timeout_ms
    next_batch = max(min_batch_size, batch_size // (2 ** attempt))
    next_timeout = int(timeout_ms * (1.5 ** attempt))
    next_timeout = max(next_timeout, timeout_ms + (attempt * 500))
    return next_batch, next_timeout


def decode_stream(value: object) -> str:
    """
    Normalize subprocess output to text.

    TimeoutExpired can surface bytes even when text mode was requested, so we
    decode defensively and keep partial output usable.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def join_process_output(stdout: object, stderr: object) -> str:
    parts = [decode_stream(stdout), decode_stream(stderr)]
    return "\n".join(part for part in parts if part)

def extract_nmap_xml(text: str) -> Optional[str]:
    if not text:
        return None

    match = re.search(r"(<\?xml.*?</nmaprun>)", text, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1)

    start = text.find("<?xml")
    end = text.rfind("</nmaprun>")
    if start != -1 and end != -1 and end > start:
        return text[start:end + len("</nmaprun>")]
    return None


def parse_rustscan_ports(output: str) -> list[int]:
    open_ports: set[int] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        patterns = (
            r"(?i)\bdiscovered open port\s+(\d{1,5})\b",
            r"(?i)\bopen port[s]?\b.*?(\d{1,5})\b",
            r"(?i)\bopen\b.*?:\s*(\d{1,5})\b",
            r"(?i)\b(\d{1,5})/(tcp|udp)\b",
        )
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    open_ports.add(int(match.group(1)))
                except ValueError:
                    pass
                break
    return sorted(open_ports)


def parse_scan_xml(xml_str: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        log("warn", f"scan XML parse error: {e}")
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


def inject_rustscan(host_results: list[dict], host: str, g: Graph, parent_id: str,
                    source: str = "rustscan"):
    level = "nmap" if source == "nmap" else "rs"
    for hr in host_results:
        ip     = hr["host"]
        ip_nid = f"ip:{ip}"

        if ip_nid not in g.nodes:
            try:    rdns, _, _ = socket.gethostbyaddr(ip)
            except: rdns = ip
            g.add_node(ip_nid, ip, "ip", {
                "ip": ip, "reverse_dns": rdns,
                "is_private": _is_private(ip), "source": source,
            })
            g.add_edge(parent_id, ip_nid, "A")

        for osm in hr["os_matches"][:2]:
            if not osm["name"]: continue
            osnid = f"os:{ip}:{osm['name'][:40]}"
            g.add_node(osnid, osm["name"][:30], "os_guess", {
                "os_name": osm["name"], "accuracy": osm["accuracy"], "host": ip,
            })
            g.add_edge(ip_nid, osnid, f"OS {osm['accuracy']}%")
            log(level, f"  OS guess: {osm['name']} ({osm['accuracy']}%)")

        for p in hr["ports"]:
            portnum     = p["port"]
            svc_name    = p["service"] or SERVICE_MAP.get(portnum, "unknown")
            version_str = " ".join(filter(None, [p["product"], p["version"], p["extrainfo"]])).strip()
            port_nid    = f"port:{ip}:{portnum}"

            g.add_node(port_nid, f":{portnum}", "port", {
                "port": portnum, "service": svc_name,
                "product": p["product"], "version": p["version"],
                "version_str": version_str, "protocol": p["protocol"],
                "cpe": p["cpe"], "host": ip, "source": source,
            })
            g.add_edge(ip_nid, port_nid, f"port/{svc_name}")

            vstr = f"{GN}{portnum}/open{R}  {YL}{svc_name}{R}"
            if version_str: vstr += f"  {GY}{version_str}{R}"
            log(level, f"  {vstr}")

            boring = {"ssl-date","ssh-hostkey","http-server-header"}
            for script in p["scripts"]:
                if not script["output"] or script["id"] in boring: continue
                snid = f"nse:{ip}:{portnum}:{script['id']}"
                g.add_node(snid, script["id"], "nse_finding", {
                    "script_id": script["id"], "output": script["output"],
                    "port": portnum, "host": ip,
                })
                g.add_edge(port_nid, snid, "NSE")
                log(level, f"  NSE [{script['id']}] {script['output'].splitlines()[0][:50]}")


def inject_rustscan_ports(host: str, ports: list[int], g: Graph, parent_id: str,
                          source: str = "rustscan"):
    level = "nmap" if source == "nmap" else "rs"
    for port in ports:
        svc = SERVICE_MAP.get(port, "unknown")
        nid = f"port:{host}:{port}"
        g.add_node(nid, f":{port}", "port", {
            "port": port, "service": svc,
            "host": host, "source": source,
            "protocol": "tcp",
        })
        g.add_edge(parent_id, nid, f"port/{svc}")
        log(level, f"  {GN}{port}/open{R}  {YL}{svc}{R}")


def run_rustscan(host: str, rustscan_bin: str, timeout_ms: int, batch_size: int,
                 is_root: bool, nmap_bin: Optional[str], greppable: bool,
                 retries: int, min_batch_size: int, nofile_soft: int,
                 process_timeout_sec: int) -> tuple[list[dict], list[int]]:
    """
    Run RustScan with optional Nmap XML handoff and return
    (structured host results, open port list).
    """
    use_nmap_xml = bool(nmap_bin) and not greppable
    if not nmap_bin and not greppable:
        log("warn", "nmap not found — using RustScan greppable output")

    host_results: list[dict] = []
    open_ports: list[int] = []

    ensure_nofile_limit(nofile_soft)

    process_timeout_sec = max(1, min(process_timeout_sec, RUSTSCAN_PROCESS_TIMEOUT_MAX))
    deadline = time.monotonic() + process_timeout_sec

    attempts: list[tuple[int, int]] = []
    cur_batch, cur_timeout = batch_size, timeout_ms
    retry_count = max(1, retries)
    for attempt in range(retry_count):
        attempts.append((cur_batch, cur_timeout))
        cur_batch, cur_timeout = rustscan_backoff(
            batch_size,
            timeout_ms,
            attempt + 1,
            min_batch_size,
        )

    best_raw = ""
    for attempt_idx, (cur_batch, cur_timeout) in enumerate(attempts, start=1):
        cmd = [
            rustscan_bin,
            "-a", host,
            "--batch-size", str(cur_batch),
            "--timeout", str(cur_timeout),
        ]
        if use_nmap_xml:
            nmap_args = ["-sV", "--version-intensity", "5", "--script", "default"]
            if is_root:
                nmap_args = ["-sS", "-O"] + nmap_args
            else:
                nmap_args = ["-sT"] + nmap_args
            nmap_args += ["-oX", "-"]
            cmd += ["--"] + nmap_args
        else:
            cmd.append("-g")

        if attempt_idx == 1:
            log("rs", f"Running RustScan for {B}{host}{R}…")
        else:
            log("rs", f"Retry {attempt_idx}/{len(attempts)} for {B}{host}{R} "
                      f"(batch={cur_batch}, timeout={cur_timeout}ms)")
        log("rs", f"  cmd: {' '.join(cmd)}")

        raw_output = ""
        returncode = 0
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log("warn", f"RustScan process budget exhausted for {host}")
                break
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=remaining,
            )
            raw_output = join_process_output(result.stdout, result.stderr)
            returncode = result.returncode
        except subprocess.TimeoutExpired as e:
            raw_output = join_process_output(e.stdout, e.stderr)
            returncode = 124
            log("warn", f"rustscan timed out on {host} — using partial results")
        except FileNotFoundError:
            log("warn", "rustscan not found on PATH")
            return [], []
        except Exception as e:
            log("err", f"rustscan error: {e}")
            return [], []

        best_raw = raw_output or best_raw

        attempt_results: list[dict] = []
        attempt_ports: list[int] = []

        if use_nmap_xml:
            xml_blob = extract_nmap_xml(raw_output)
            if xml_blob:
                attempt_results = parse_scan_xml(xml_blob)
                for hr in attempt_results:
                    attempt_ports.extend([p["port"] for p in hr["ports"]])
            elif attempt_idx == 1:
                log("warn", f"RustScan output for {host} did not include Nmap XML")

        if not attempt_ports:
            attempt_ports = parse_rustscan_ports(raw_output)

        if attempt_results:
            host_results = attempt_results
        if attempt_ports:
            open_ports = sorted(set(open_ports + attempt_ports))

        reason = rustscan_retry_reason(raw_output, returncode)
        if reason:
            if reason in {"ulimit", "nofile", "resources"}:
                ensure_nofile_limit(nofile_soft)
            log("warn", f"RustScan {reason} hint on {host} (attempt {attempt_idx}/{len(attempts)})")
            if attempt_idx < len(attempts):
                continue

        if attempt_results or attempt_ports:
            break

    open_ports = sorted(set(open_ports))
    if host_results:
        log("rs", f"  {GN}{len(open_ports)}{R} open ports with service/version data")
    elif open_ports:
        log("rs", f"  {GN}{len(open_ports)}{R} open ports")
    else:
        if best_raw:
            log("warn", f"RustScan produced output for {host} but no ports could be parsed")
        else:
            log("warn", f"RustScan produced no usable output for {host}")

    return host_results, open_ports


def run_nmap_scan(host: str, nmap_bin: str, is_root: bool,
                  timeout_sec: int, ports: Optional[list[int]] = None) -> tuple[list[dict], list[int]]:
    """
    Run Nmap as a fallback after RustScan fails.
    """
    nmap_args = ["-sV", "-sC"]
    if is_root:
        nmap_args = ["-sS", "-O"] + nmap_args
    else:
        nmap_args = ["-sT"] + nmap_args
    cmd = [nmap_bin]
    if ports:
        ports = sorted(set(ports))
        if not ports:
            return [], []
        cmd += ["-p", ",".join(str(p) for p in ports)]
    else:
        cmd += ["-p-"]
    cmd += nmap_args + ["-oX", "-", host]

    port_desc = "all ports" if not ports else f"{len(ports)} ports"
    log("nmap", f"Running Nmap fallback for {B}{host}{R} on {port_desc}…")
    log("nmap", f"  cmd: {' '.join(cmd)}")

    raw_output = ""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=max(120, min(timeout_sec, RUSTSCAN_PROCESS_TIMEOUT_MAX)),
        )
        raw_output = join_process_output(result.stdout, result.stderr)
    except subprocess.TimeoutExpired as e:
        raw_output = join_process_output(e.stdout, e.stderr)
        log("warn", f"nmap timed out on {host} — using partial results")
    except FileNotFoundError:
        log("warn", "nmap not found on PATH")
        return [], []
    except Exception as e:
        log("err", f"nmap error: {e}")
        return [], []

    xml_blob = extract_nmap_xml(raw_output)
    if not xml_blob:
        if raw_output:
            log("warn", f"Nmap output for {host} did not include XML")
        return [], []

    host_results = parse_scan_xml(xml_blob)
    open_ports: list[int] = []
    for hr in host_results:
        open_ports.extend([p["port"] for p in hr["ports"]])
    return host_results, sorted(set(open_ports))


def parse_naabu_ports(output: str) -> list[int]:
    ports: set[int] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                data = json.loads(line)
                port = data.get("port")
                if port is not None:
                    ports.add(int(port))
                    continue
            except Exception:
                pass
        match = re.search(r":(\d{1,5})\b", line)
        if match:
            try:
                ports.add(int(match.group(1)))
            except ValueError:
                pass
    return sorted(ports)


def run_naabu(host: str, naabu_bin: str, timeout_ms: int, process_timeout_sec: int) -> list[int]:
    """
    Run Naabu port discovery and return a port list.
    """
    log("naabu", f"Running Naabu for {B}{host}{R}…")
    cmd = [
        naabu_bin,
        "-host", host,
        "-p", "-",
        "-json",
        "-silent",
        "-timeout", str(max(250, timeout_ms)),
    ]
    log("naabu", f"  cmd: {' '.join(cmd)}")

    process_timeout_sec = max(1, min(process_timeout_sec, RUSTSCAN_PROCESS_TIMEOUT_MAX))
    raw_output = ""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=process_timeout_sec,
        )
        raw_output = join_process_output(result.stdout, result.stderr)
    except subprocess.TimeoutExpired as e:
        raw_output = join_process_output(e.stdout, e.stderr)
        log("warn", f"naabu timed out on {host} — using partial results")
    except FileNotFoundError:
        log("warn", "naabu not found on PATH")
        return []
    except Exception as e:
        log("err", f"naabu error: {e}")
        return []

    return parse_naabu_ports(raw_output)


def run_fallback_scans(host: str, fallback_ports: list[int], g: Graph, parent_id: str,
                       timeout: int, threads: int, nmap_bin: Optional[str],
                       is_root: bool, use_socket: bool,
                       rustscan_process_timeout: int) -> tuple[list[int], bool, bool, int]:
    """
    Run fallback scanning after RustScan fails.
    Prefer a full Nmap scan, then fall back to the socket scanner if needed.
    """
    fallback_ports = list(fallback_ports)

    nmap_results: list[dict] = []
    nmap_ports: list[int] = []
    used_nmap = False
    used_socket = False
    socket_open_count = 0
    if nmap_bin:
        nmap_results, nmap_ports = run_nmap_scan(
            host,
            nmap_bin,
            is_root,
            rustscan_process_timeout,
            None,
        )
        if nmap_results:
            inject_rustscan(nmap_results, host, g, parent_id, source="nmap")
            used_nmap = True
        elif nmap_ports:
            inject_rustscan_ports(host, nmap_ports, g, parent_id, source="nmap")
            used_nmap = True

    if nmap_ports:
        return sorted(set(nmap_ports)), used_nmap, used_socket, socket_open_count

    if use_socket and fallback_ports:
        log("info", f"  Starting socket fallback on {len(fallback_ports)} ports")
        socket_ports = socket_scan(host, fallback_ports, g, parent_id, timeout, threads)
        used_socket = True
        socket_open_count = len(socket_ports)
        return socket_ports, used_nmap, used_socket, socket_open_count

    if not nmap_bin:
        log("warn", "nmap not found on PATH — fallback Nmap scan skipped")
    elif not use_socket:
        log("info", "  Socket fallback disabled")

    return [], used_nmap, used_socket, socket_open_count

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
#  SCAN HOST  — rustscan + socket (merged)
# ══════════════════════════════════════════════════════════════════════════════

def scan_host(host: str, fallback_ports: list[int], g: Graph, parent_id: str,
              timeout: int, threads: int,
              rustscan_bin: Optional[str],
              naabu_bin: Optional[str],
              nmap_bin: Optional[str],
              is_root: bool, use_stealth: bool, use_rustscan: bool, use_socket: bool,
              rustscan_greppable: bool, rustscan_batch_size: int,
              rustscan_timeout: int, rustscan_retries: int,
              rustscan_min_batch_size: int, rustscan_nofile_soft: int,
              rustscan_process_timeout: int) -> list[int]:

    # Stealth mode uses Naabu first. Normal mode keeps RustScan as the fast
    # discovery front-end.
    if use_stealth:
        if naabu_bin:
            naabu_ports = run_naabu(host, naabu_bin, timeout * 1000, rustscan_process_timeout)
            if naabu_ports:
                if nmap_bin:
                    nmap_results, nmap_ports = run_nmap_scan(
                        host,
                        nmap_bin,
                        is_root,
                        rustscan_process_timeout,
                        naabu_ports,
                    )
                    if nmap_results:
                        inject_rustscan(nmap_results, host, g, parent_id, source="nmap")
                        return sorted(set(nmap_ports or naabu_ports))
                    if nmap_ports:
                        inject_rustscan_ports(host, nmap_ports, g, parent_id, source="nmap")
                        return sorted(set(nmap_ports))
                inject_rustscan_ports(host, naabu_ports, g, parent_id, source="naabu")
                return sorted(set(naabu_ports))

            log("warn", f"Naabu returned no usable ports for {host}")
        else:
            log("warn", "naabu not found on PATH")

        all_open, used_nmap, used_socket, socket_open_count = run_fallback_scans(
            host,
            fallback_ports,
            g,
            parent_id,
            timeout,
            threads,
            nmap_bin,
            is_root,
            use_socket,
            rustscan_process_timeout,
        )
        if all_open:
            sources = []
            if used_nmap:
                sources.append("nmap=full")
            if used_socket:
                sources.append(f"socket={socket_open_count}")
            log("merge", f"  open={len(all_open)}  " + "  ".join(sources))
        return all_open

    # RustScan is the gatekeeper in normal mode. Fallback scans only run after
    # all retries fail to produce any usable port data.
    if use_rustscan and rustscan_bin:
        rustscan_results, rustscan_ports = run_rustscan(
            host,
            rustscan_bin,
            rustscan_timeout,
            rustscan_batch_size,
            is_root,
            nmap_bin,
            rustscan_greppable,
            rustscan_retries,
            rustscan_min_batch_size,
            rustscan_nofile_soft,
            rustscan_process_timeout,
        )

        if rustscan_results:
            inject_rustscan(rustscan_results, host, g, parent_id, source="rustscan")
            return sorted(set(rustscan_ports))
        if rustscan_ports:
            inject_rustscan_ports(host, rustscan_ports, g, parent_id, source="rustscan")
            return sorted(set(rustscan_ports))

        log("warn", f"RustScan exhausted all retries for {host} with no usable ports")
        all_open, used_nmap, used_socket, socket_open_count = run_fallback_scans(
            host,
            fallback_ports,
            g,
            parent_id,
            timeout,
            threads,
            nmap_bin,
            is_root,
            use_socket,
            rustscan_process_timeout,
        )
        if all_open:
            sources = []
            if used_nmap:
                sources.append("nmap=full")
            if used_socket:
                sources.append(f"socket={socket_open_count}")
            log("merge", f"  open={len(all_open)}  " + "  ".join(sources))
        return all_open

    if not use_rustscan:
        log("info", "  RustScan skipped — using fallback scans")
        all_open, _, _, _ = run_fallback_scans(
            host,
            fallback_ports,
            g,
            parent_id,
            timeout,
            threads,
            nmap_bin,
            is_root,
            use_socket,
            rustscan_process_timeout,
        )
        return all_open

    log("warn", "  RustScan not found — using fallback scans")
    all_open, _, _, _ = run_fallback_scans(
        host,
        fallback_ports,
        g,
        parent_id,
        timeout,
        threads,
        nmap_bin,
        is_root,
        use_socket,
        rustscan_process_timeout,
    )
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
        description="netmalper v8 — amass + rustscan + naabu recon graph mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("target")
    ap.add_argument("--version", action="version", version=f"netmalper {VERSION}")
    ap.add_argument("--subdomains",     default=None,
                    help="Extra wordlist file — merged with built-in list")
    ap.add_argument("--out",            default=None)
    ap.add_argument("--timeout",        type=int, default=3)
    ap.add_argument("--threads",        type=int, default=30)
    ap.add_argument("--amass-timeout",  type=int, default=1800,
                    help="Amass active-mode timeout in seconds (default: 1800)")
    ap.add_argument("--stealth",        action="store_true",
                    help="Use Naabu + Nmap deep scanning and passive Amass")
    ap.add_argument("--no-amass",       action="store_true")
    ap.add_argument("--no-wordlist",    action="store_true")
    ap.add_argument("--no-rustscan",    action="store_true",
                    help="Skip RustScan and use the socket scanner only")
    ap.add_argument("--rustscan-greppable", action="store_true",
                    help="Parse RustScan's greppable output instead of Nmap XML")
    ap.add_argument("--rustscan-batch-size", type=int, default=4500,
                    help="RustScan batch size (default: 4500)")
    ap.add_argument("--rustscan-timeout", type=int, default=1500,
                    help="RustScan timeout in milliseconds (default: 1500)")
    ap.add_argument("--rustscan-process-timeout", type=int, default=1800,
                    help="RustScan total process budget in seconds (default: 1800, max: 1800)")
    ap.add_argument("--rustscan-retries", type=int, default=3,
                    help="RustScan retry attempts (default: 3)")
    ap.add_argument("--rustscan-min-batch-size", type=int, default=128,
                    help="Minimum RustScan batch size on retries (default: 128)")
    ap.add_argument("--rustscan-nofile-soft", type=int, default=8192,
                    help="Soft RLIMIT_NOFILE floor to try to raise to (default: 8192)")
    ap.add_argument("--no-socket",      action="store_true")
    ap.add_argument("--no-http",        action="store_true")
    ap.add_argument("--no-ports",       action="store_true")
    ap.add_argument("--no-subs",        action="store_true")
    ap.add_argument("--no-dns",         action="store_true")
    ap.add_argument("--open-viewer",    action="store_true")
    ap.add_argument("--viewer",         default="netmalper_visualizer.html")
    args = ap.parse_args()

    # ── sanitize target ───────────────────────────────────────────────────────
    target = args.target.lower().strip()
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0].split('?')[0].rstrip('.')
    safe_name = re.sub(r'[^\w.\-]', '_', target)
    out_path  = args.out or f"{safe_name}_graph.json"
    args.viewer = resolve_viewer(args.viewer)

    # ── detect tools ──────────────────────────────────────────────────────────
    is_root   = check_root()
    rustscan_bin = find_tool("rustscan") if not args.no_rustscan else None
    naabu_bin    = find_tool("naabu") if args.stealth else None
    nmap_bin     = find_tool("nmap")
    amass_bin    = find_tool("amass") if not args.no_amass else None

    use_stealth  = bool(args.stealth)
    use_rustscan = bool(rustscan_bin) and not args.no_rustscan and not use_stealth
    use_naabu    = bool(naabu_bin) and use_stealth
    use_amass    = bool(amass_bin) and not args.no_amass
    use_socket   = not args.no_socket
    use_wordlist = not args.no_wordlist
    amass_passive = use_stealth
    amass_timeout = 3600 if use_stealth else args.amass_timeout

    banner(target, use_rustscan, use_naabu, use_amass, is_root, use_stealth)

    if use_stealth and use_naabu:
        log("naabu", f"{MG}Naabu stealth mode enabled{R}")
    elif use_rustscan and is_root:
        log("rs", f"{GN}SYN scan + OS fingerprinting enabled (root){R}")
    elif use_rustscan:
        log("warn", "Non-root: using -sT (TCP connect), no OS fingerprint")

    if use_stealth and not naabu_bin:
        log("warn", "naabu not found — stealth mode will fall back to Nmap/socket scanning")
        log("warn", "  install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")

    if use_stealth and not nmap_bin:
        log("warn", "nmap not found — stealth mode will fall back to socket/full scan if Naabu fails")
    elif use_rustscan and not nmap_bin:
        log("warn", "nmap not found — fallback Nmap scan will be unavailable if RustScan fails")

    if not use_stealth and not rustscan_bin and not args.no_rustscan:
        log("warn", "rustscan not found — using socket scanner only")
        log("warn", "  install: cargo install rustscan")

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

    # ── 2. Subdomain enumeration (amass + wordlist, parallel) ────────────────
    found_subs: list[str] = []
    if not args.no_subs:
        log("info", f"{'─'*50}")
        log("info", f"Subdomain enumeration  "
                    f"[amass={'passive' if amass_passive else 'active' if use_amass else 'skip'}  "
                    f"wordlist={'yes' if use_wordlist else 'skip'}]")
        found_subs = enum_subdomains(
            target, g, root_id,
            amass_bin, wordlist,
            args.timeout, args.threads,
            use_amass, use_wordlist,
            amass_timeout,
            amass_passive,
        )

    # ── 3. Port scanning: rustscan + socket ──────────────────────────────────
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
            scan_mode = "naabu+nmap+fallback" if use_stealth else ("rustscan+socket" if use_rustscan else "socket")
            log("info", f"Scanning {B}{st}{R}  [{scan_mode}]")
            open_p = scan_host(
                st, fallback_ports, g, parent,
                args.timeout, args.threads,
                rustscan_bin, naabu_bin, nmap_bin,
                is_root, use_stealth, use_rustscan, use_socket,
                args.rustscan_greppable, args.rustscan_batch_size,
                args.rustscan_timeout, args.rustscan_retries,
                args.rustscan_min_batch_size,
                args.rustscan_nofile_soft,
                args.rustscan_process_timeout,
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
        "rustscan_used": use_rustscan,
        "rustscan_retries": args.rustscan_retries,
        "rustscan_batch_size": args.rustscan_batch_size,
        "rustscan_min_batch_size": args.rustscan_min_batch_size,
        "rustscan_nofile_soft": args.rustscan_nofile_soft,
        "rustscan_timeout_ms": args.rustscan_timeout,
        "amass_used":   use_amass,
        "amass_passive": amass_passive,
        "amass_timeout_s": amass_timeout,
        "stealth_used":  use_stealth,
        "nmap_used":    bool(nmap_bin),
        "naabu_used":    use_naabu,
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
  {GN}amass      :{R} {GN+(('passive ✓' if amass_passive else 'active ✓'))+R if use_amass else GY+'skipped'+R}
  {GN}stealth    :{R} {GN+'✓'+R if use_stealth else GY+'off'+R}
  {GN}rustscan   :{R} {GN+'✓'+R if use_rustscan else GY+'skipped (naabu/socket fallback)'+R}
  {GN}root scan  :{R} {GN+'SYN+OS'+R if is_root else YL+'TCP connect'+R}
  {GN}output     :{R} {out_path}
{CY}{'─'*54}{R}
""")

    if args.open_viewer and args.viewer and os.path.exists(args.viewer):
        import webbrowser
        graph_uri = Path(out_path).resolve().as_uri()
        webbrowser.open(
            f"file://{os.path.abspath(args.viewer)}"
            f"?graph={urllib.parse.quote(graph_uri, safe='')}"
        )

    return out_path

def entry() -> int:
    """Console-script entry point: run a scan and exit cleanly."""
    main()
    return 0

if __name__ == "__main__":
    main()
