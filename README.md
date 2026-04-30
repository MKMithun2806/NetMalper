## <p align="left"><img src="debian/logo.svg" alt="NETMALPER" height="500"></p>
![License](https://img.shields.io/badge/license-MIT-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20MacOS-black.svg)
![Status](https://img.shields.io/badge/version-3.0.2--stable-orange)

**Automated Reconnaissance & 3D Intelligence Mapping**

---

# Features
- Zero-Config Scanning: Automatic dependency handling via Docker.
- Multi-Arch Support: Tested on Raspberry Pi 4B (ARM64) and high-performance x86 nodes.
- Visual Integration: Native JSON support for force-directed graph mapping.

Maintained by: MKMithun2806 | Red Team Aspirant & Security Researcher

# Visualization
- NetMalper doesn't just give you a wall of text. It generates a structured intelligence map.
- Run a scan with the --output scan.json flag ( For Docker only )
- Upload the resulting file to the [NetMalper 3D Visualizer](http://threejs-rubiks-cube-mitch.s3-website.ap-south-2.amazonaws.com).
- Explore your target's attack surface in an interactive Three.js environment.

---

### Flags

| Flag | Effect |
|------|--------|
| `--ports PORTS` | Specify ports to scan. Supports lists (`80,443`) or ranges (`1-1024`). |
| `--subdomains FILE` | Provide a wordlist file for subdomain brute-force. |
| `--out FILE` | Output JSON file path. Default: `<target>_graph.json`. |
| `--timeout SEC` | Per-probe timeout in seconds. Default: `3`. |
| `--threads N` | Number of threads for socket scanning. Default: `30`. |
| `--nmap-timing {1-5}` | Control Nmap timing template (1 = slow/stealthy, 5 = fast/aggressive). Default: `4`. |
| `--no-nmap` | Disable Nmap scanning entirely (socket-only mode). |
| `--no-socket` | Disable socket scanner (Nmap-only mode). |
| `--no-http` | Skip HTTP endpoint probing. |
| `--no-ports` | Skip all port scanning. |
| `--no-subs` | Skip subdomain enumeration. |
| `--no-dns` | Skip DNS resolution and chain mapping. |
| `--open-viewer` | Automatically open the HTML graph viewer after scan. |
| `--viewer FILE` | Specify custom path to `netmalper_viewer.html`. |
| `--naabu-ports 1-10000` | scan only first 10k ports (faster) |
| `--naabu-rate 2000` | packets/sec (raise for fast networks) |
| `--no-amass` | Skip Amass |
| `--amass-timeout 180` | give amass more time on big targets |
| `--no-wordlist` | amass only |
| `--no-naabu` | skip discovery, use default port list |


---

# How To Use:

## QuickStart ( To Try the tool )
*The easiest way to run NetMalper without installing dependencies is by using docker:*
```bash
docker run --rm -it --network host -v $(pwd):/app mitchaster/malper-suite:latest nmap.scanme.org
```

---

## Native Installation ( Recommended For Use )
To install NetMalper on any **Debian-based** system (Ubuntu, Kali, Raspberry Pi OS), run:

```bash
LATEST_DEB=$(curl -s https://api.github.com/repos/MKMithun2806/NetMalper/releases/latest | jq -r '.assets[] | select(.name | endswith(".deb")) | .browser_download_url') \
&& wget -qO netmalper.deb "$LATEST_DEB" \
&& sudo apt install -y ./netmalper.deb \
&& rm netmalper.deb
```

## For Macs

```bash
brew install nmap python3 && curl -L -o NetMalper "https://raw.githubusercontent.com/MKMithun2806/NetMalper/main/netmalper.py" && chmod +x NetMalper && sudo mv NetMalper /usr/local/bin/
```

*To run ( U might get errors about therool being from an unknown dev*

```bash
NetMalper <target_ip_or_subnet> --out graph.json
```
---

## For Windows ( Requires Admin )

```bash
winget install nmap ; pip install python-nmap ; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MKMithun2806/NetMalper/main/netmalper.py" -OutFile "NetMalper.py"
```
*Note: On Windows, Youll have to will run it using*
```bash
python NetMalper.py
```
