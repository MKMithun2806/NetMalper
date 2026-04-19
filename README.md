# Installation

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

## For Docker

No Install needed for this just run it

```bash
docker run --rm -it --network host -v $(pwd):/app mitchaster/netmalper:latest <target> --output scan.json
```

# Vizualizer

It is live on [NetMalper Visualizer](http://threejs-rubiks-cube-mitch.s3-website.ap-south-2.amazonaws.com/?hl=en-IN)

