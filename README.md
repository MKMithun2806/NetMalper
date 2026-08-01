## <p align="left"><img src="debian/logo.svg" alt="NETMALPER" height="500"></p>
![License](https://img.shields.io/badge/license-MIT-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20MacOS-black.svg)
![Status](https://img.shields.io/badge/version-8.0.0--stable-orange)

**Automated Reconnaissance & 3D Intelligence Mapping**

---

<img width="2559" height="1599" alt="capture_20260603_120907" src="https://github.com/user-attachments/assets/4b6f4505-5ca9-4971-aac0-aceab0e7b608" />

---

# Features
- **Hybrid Subdomain Discovery**: Merges Amass active mode by default with passive mode in `--stealth`, plus high-speed DNS brute-forcing.
- **Advanced Port Scanning**: Standard mode uses RustScan-first discovery with Nmap handoff. `--stealth` skips RustScan and sends Naabu-discovered ports straight to Nmap for deep scanning.
- **Controlled Fallbacks**: Socket and full-Nmap scans stay idle until the primary scanner exhausts all retries or returns no usable ports.
- **Visual Intelligence**: Generates interactive, force-directed graph maps for complex network visualization.
- **Resilient**: Automatic `ulimit` (NOFILE) handling and intelligent backoff for high-concurrency scans.

Maintained by: MKMithun2806 | Red Team Aspirant & Security Researcher

# Visualization
- NetMalper generates a structured intelligence map instead of a wall of text.
- Run a scan with `--out scan.json`, then open [NetMalper Viewer](https://mkmithun2806.github.io/NetMalper/netmalper_visualizer.html) or the legacy [NetMalper Vizualizer](http://threejs-rubiks-cube-mitch.s3-website.ap-south-2.amazonaws.com/) 
or use `--open-viewer`.
- The visualizer uses React Flow for pan/zoom, filtering, connected-node focus, and scan metadata panels.

---

### Flags

| Flag | Effect |
|------|--------|
| `target` | The target domain or IP address to scan. |
| `--subdomains FILE` | Extra wordlist file for subdomain brute-force (merged with built-in list). |
| `--out FILE` | Output JSON file path. Default: `<target>_graph.json`. |
| `--timeout SEC` | Per-probe timeout in seconds. Default: `3`. |
| `--threads N` | Thread count for parallel tasks. Default: `30`. |
| `--amass-timeout SEC` | Amass active-mode timeout in seconds. Default: `1800`. `--stealth` switches Amass to passive mode with a `3600` second timeout. |
| `--stealth` | Skip RustScan, use Naabu for port discovery, then send discovered ports straight to Nmap for deep scanning. |
| `--no-amass` | Skip Amass enumeration. |
| `--no-wordlist` | Skip built-in + custom wordlist brute-force. |
| `--no-rustscan` | Skip RustScan and use the socket scanner only. |
| `--rustscan-batch-size N` | RustScan batch size. Default: `4500`. |
| `--rustscan-timeout MS` | RustScan internal timeout in milliseconds. Default: `1500`. |
| `--rustscan-process-timeout SEC` | Total RustScan process budget across retries. Default: `1800`, max `1800`. |
| `--rustscan-retries N` | RustScan retry attempts on failure. Default: `3`. |
| `--rustscan-greppable` | Parse RustScan's greppable output instead of Nmap XML. |
| `--no-socket` | Skip the parallel socket scanner fallback. |
| `--no-http` | Skip HTTP endpoint probing. |
| `--no-ports` | Skip all port scanning. |
| `--no-subs` | Skip subdomain enumeration. |
| `--no-dns` | Skip DNS chain resolution. |
| `--open-viewer` | Automatically open the HTML graph viewer after scan. |
| `--viewer FILE` | Specify custom path to `netmalper_visualizer.html`. |

---

# How To Use:

## Install (Python)
NetMalper is a standard Python project — install it with `pip` or `uv`:

```bash
# from this repository
pip install .
netmalper <target>

# or with uv
uv tool install .
netmalper <target>
```

## QuickStart (Docker)
*The easiest way to run NetMalper without installing dependencies:*
```bash
docker run --rm -it --network host -v $(pwd):/app ghcr.io/MKMithun2806/NetMalper:latest <target>
```

### Stealth Mode
`--stealth` requires `naabu` and `nmap` in your PATH. In this mode NetMalper:
- runs Amass in passive mode with a 1 hour timeout
- skips RustScan entirely
- scans ports with Naabu
- hands Naabu-discovered ports straight to Nmap for deeper analysis

---

## Native Installation (Debian/Ubuntu/Kali)
To install NetMalper natively, run:

```bash
URL=$(curl -s https://api.github.com/repos/MKMithun2806/NetMalper/releases | grep browser_download_url | grep .deb | cut -d '"' -f 4 | head -n 1) && \
curl -L -o netmalper.deb "$URL" && \
sudo apt install -y ./netmalper.deb && \
rm -f netmalper.deb
```

For `--stealth`, also install Naabu:
```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

## For MacOS

```bash
brew install nmap rustscan amass python3 libpcap
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
git clone https://github.com/MKMithun2806/NetMalper.git && cd NetMalper
pip install .
netmalper <target>
```

## For Windows (Requires Admin)

```bash
winget install nmap rustscan
# Install Npcap before using Naabu on Windows.
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
git clone https://github.com/MKMithun2806/NetMalper.git && cd NetMalper
pip install .
netmalper <target>
```
