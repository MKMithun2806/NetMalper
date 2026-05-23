## <p align="left"><img src="debian/logo.svg" alt="NETMALPER" height="500"></p>
![License](https://img.shields.io/badge/license-MIT-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20MacOS-black.svg)
![Status](https://img.shields.io/badge/version-3.0.0--stable-orange)

**Automated Reconnaissance & 3D Intelligence Mapping**

---

# Features
- **Hybrid Subdomain Discovery**: Merges Amass passive OSINT with high-speed DNS brute-forcing.
- **Advanced Port Scanning**: Native RustScan integration for ultra-fast discovery with Nmap service/version fingerprinting fallback.
- **Visual Intelligence**: Generates interactive, force-directed graph maps for complex network visualization.
- **Resilient**: Automatic `ulimit` (NOFILE) handling and intelligent backoff for high-concurrency scans.

Maintained by: MKMithun2806 | Red Team Aspirant & Security Researcher

# Visualization
- NetMalper generates a structured intelligence map instead of a wall of text.
- Run a scan with `--out scan.json`, then open [NetMalper Viewer](https://mkmithun2806.github.io/NetMalper/netmalper_vizualizer.html) or the legacy [NetMalper Vizualizer](http://threejs-rubiks-cube-mitch.s3-website.ap-south-2.amazonaws.com/) or use `--open-viewer`.
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
| `--amass-timeout SEC` | Amass passive scan timeout in seconds. Default: `120`. |
| `--no-amass` | Skip Amass passive enumeration. |
| `--no-wordlist` | Skip built-in + custom wordlist brute-force. |
| `--no-rustscan` | Skip RustScan and use the socket scanner only. |
| `--rustscan-batch-size N` | RustScan batch size. Default: `4500`. |
| `--rustscan-timeout MS` | RustScan timeout in milliseconds. Default: `1500`. |
| `--rustscan-retries N` | RustScan retry attempts on failure. Default: `3`. |
| `--no-socket` | Skip the parallel socket scanner fallback. |
| `--no-http` | Skip HTTP endpoint probing. |
| `--no-ports` | Skip all port scanning. |
| `--no-subs` | Skip subdomain enumeration. |
| `--no-dns` | Skip DNS chain resolution. |
| `--open-viewer` | Automatically open the HTML graph viewer after scan. |
| `--viewer FILE` | Specify custom path to `netmalper_vizualizer.html`. |

---

# How To Use:

## QuickStart (Docker)
*The easiest way to run NetMalper without installing dependencies:*
```bash
docker run --rm -it --network host -v $(pwd):/app mitchaster/malper-suite:latest <target>
```

---

## Native Installation (Debian/Ubuntu/Kali)
To install NetMalper natively, run:

```bash
URL=$(curl -s https://api.github.com/repos/MKMithun2806/NetMalper/releases | grep browser_download_url | grep .deb | cut -d '"' -f 4 | head -n 1) && \
curl -L -o netmalper.deb "$URL" && \
sudo apt install -y ./netmalper.deb && \
rm -f netmalper.deb
```

## For MacOS

```bash
brew install nmap rustscan amass python3
curl -L -o NetMalper "https://raw.githubusercontent.com/MKMithun2806/NetMalper/main/netmalper.py"
chmod +x NetMalper
sudo mv NetMalper /usr/local/bin/
```

## For Windows (Requires Admin)

```bash
winget install nmap rustscan
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MKMithun2806/NetMalper/main/netmalper.py" -OutFile "netmalper.py"
python netmalper.py <target>
```
