# ==============================================================================
# STAGE 1: Build RustScan
# ==============================================================================
FROM rust:bookworm AS rustbuilder

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN git clone --depth 1 https://github.com/RustScan/RustScan.git rustscan && \
    cd rustscan && \
    cargo build --release && \
    mkdir -p /out && \
    install -Dm755 target/release/rustscan /out/rustscan && \
    test -x /out/rustscan


# ==============================================================================
# STAGE 2: Build Go Tools
# ==============================================================================
FROM golang:1.26-bookworm AS gobuilder

ARG TARGETOS
ARG TARGETARCH

# Unset GOBIN to allow cross-compilation target directories
ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

WORKDIR /src

RUN mkdir -p /out && \
    # 1. Install ProjectDiscovery tools using standard go install
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    \
    # 2. Build Amass v5 from source
    git clone --depth 1 https://github.com/owasp-amass/amass.git && \
    cd amass && \
    go build -v -o /out/amass ./cmd/amass && \
    cd /src && \
    \
    # 3. Locate and copy tools from standard or arch-specific paths
    if [ -d "/go/bin/${TARGETOS}_${TARGETARCH}" ]; then \
        cp /go/bin/${TARGETOS}_${TARGETARCH}/httpx /out/httpx && \
        cp /go/bin/${TARGETOS}_${TARGETARCH}/naabu /out/naabu; \
    else \
        cp /go/bin/httpx /out/httpx && \
        cp /go/bin/naabu /out/naabu; \
    fi && \
    \
    # 4. Final verification
    test -x /out/httpx && \
    test -x /out/amass && \
    test -x /out/naabu


# ==============================================================================
# STAGE 3: Final Runtime
# ==============================================================================
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    libpcap0.8 \
    curl \
    git \
    procps \
    iproute2 \
    ca-certificates \
    jq \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=rustbuilder /out/rustscan /usr/local/bin/rustscan
COPY --from=gobuilder /out/httpx /usr/local/bin/httpx
COPY --from=gobuilder /out/amass /usr/local/bin/amass
COPY --from=gobuilder /out/naabu /usr/local/bin/naabu

RUN chmod +x /usr/local/bin/rustscan /usr/local/bin/httpx /usr/local/bin/amass /usr/local/bin/naabu

# Wordlists
RUN mkdir -p /app/wordlists && \
    curl -fsSL https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-1000.txt \
      -o /app/wordlists/subdomains-small.txt && \
    curl -fsSL https://raw.githubusercontent.com/nmap/nmap/master/nselib/data/vhosts-default.lst \
      -o /app/wordlists/vhosts.txt

# NetMalper installation — built from the repo source so the image always
# matches the code being shipped (no external .deb download).
ARG RELEASE_TAG=latest
LABEL org.opencontainers.image.title="netmalper" \
      org.opencontainers.image.description="Automated Reconnaissance & 3D Intelligence Mapping" \
      org.opencontainers.image.version="${RELEASE_TAG}" \
      org.opencontainers.image.source="https://github.com/MKMithun2806/NetMalper"

COPY pyproject.toml README.md LICENSE ./
COPY netmalper/ ./netmalper/
COPY netmalper_vizualizer.html ./

RUN pip install --no-cache-dir . && \
    rm -rf netmalper netmalper_vizualizer.html README.md LICENSE pyproject.toml *.egg-info

ENV WORDLIST_PATH="/app/wordlists/subdomains-small.txt"

# Final sanity checks (Amass version check removed due to v5 CLI changes)
RUN rustscan --version && \
    httpx -version && \
    naabu -version && \
    netmalper --version

ENTRYPOINT ["netmalper"]
