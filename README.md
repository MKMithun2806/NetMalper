<p align="left">
  <img src="https://readme-typing-svg.demolab.com?font=Syne&weight=800&size=45&duration=1&pause=0&color=FF6B6B&width=435&lines=NET%3Cspan+style%3D%22color%3A%236B6B8A%3B+font-weight%3A400%22%3EMALPER%3C%2Fspan%3E" alt="NETMALPER" />
</p>

**Automated Reconnaissance & 3D Intelligence Mapping**

---

# Features
- Zero-Config Scanning: Automatic dependency handling via Docker.
- Red Team Ready: Optimized for system shell and infrastructure reconnaissance.
- Multi-Arch Support: Tested on Raspberry Pi 4B (ARM64) and high-performance x86 nodes.
- Visual Integration: Native JSON support for force-directed graph mapping.

Maintained by: MKMithun2806 | Red Team Aspirant & Security Researcher

# Visualization
- NetMalper doesn't just give you a wall of text. It generates a structured intelligence map.
- Run a scan with the --output scan.json flag ( For Docker only )
- Upload the resulting file to the [NetMalper 3D Visualizer](http://threejs-rubiks-cube-mitch.s3-website.ap-south-2.amazonaws.com).
- Explore your target's attack surface in an interactive Three.js environment.

# How To Use:

## QuickStart
*The easiest way to run NetMalper without installing dependencies:*
```bash
docker run --rm -it --network host -v $(pwd):/data mitchaster/netmalper:latest nmap.scanme.org --out /data/scan.json

```
## Native Installation 
To install NetMalper on any **Debian-based** system (Ubuntu, Kali, Raspberry Pi OS), run:

```bash
wget -qO netmalper.deb "https://github.com/MKMithun2806/NetMalper/releases/download/Stable-V1/netmalper_2.0.0_all.deb" && sudo apt install ./netmalper.deb && rm netmalper.deb
```

## For Macs

```bash
brew install nmap python3 && curl -L -o NetMalper "https://raw.githubusercontent.com/MKMithun2806/NetMalper/main/netmalper.py" && chmod +x NetMalper && sudo mv NetMalper /usr/local/bin/
```

## For Windows ( Requires Admin )

```bash
winget install nmap ; pip install python-nmap ; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MKMithun2806/NetMalper/main/netmalper.py" -OutFile "NetMalper.py"
```
*Note: On Windows, Youll have to will run it using python NetMalper.py*
