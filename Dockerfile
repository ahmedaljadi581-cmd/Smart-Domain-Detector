FROM golang:1.25-bookworm AS go-tools

ENV GOBIN=/opt/go-tools/bin

RUN mkdir -p /opt/go-tools/bin

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
  && go install github.com/owasp-amass/amass/v4/...@latest \
  && go install github.com/tomnomnom/assetfinder@latest \
  && go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest \
  && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
  && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
  && go install github.com/projectdiscovery/katana/cmd/katana@latest \
  && go install github.com/lc/gau/v2/cmd/gau@latest \
  && go install github.com/d3mondev/puredns/v2@latest \
  && go install github.com/PentestPad/subzy@latest \
  && go install github.com/tomnomnom/waybackurls@latest

FROM debian:bookworm-slim AS massdns-builder

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential ca-certificates git make \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
  && make -C /tmp/massdns \
  && install -m 0755 /tmp/massdns/bin/massdns /usr/local/bin/massdns

FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    gcc \
    g++ \
    libffi-dev \
    libpcap-dev \
    libssl-dev \
    make \
    python3 \
    python3-pip \
    python3-venv \
    unzip \
    wget \
    whois \
  && rm -rf /var/lib/apt/lists/*

COPY --from=go-tools /opt/go-tools/bin/ /usr/local/bin/
COPY --from=massdns-builder /usr/local/bin/massdns /usr/local/bin/massdns

RUN mkdir -p /opt/findomain \
  && curl -fsSL https://github.com/Findomain/Findomain/releases/download/10.0.1/findomain-linux.zip -o /tmp/findomain-linux.zip \
  && unzip -q /tmp/findomain-linux.zip -d /opt/findomain \
  && install -m 0755 /opt/findomain/findomain /usr/local/bin/findomain \
  && rm -rf /tmp/findomain-linux.zip /opt/findomain

RUN python3 -m venv /opt/pytools \
  && /opt/pytools/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
  && /opt/pytools/bin/pip install --no-cache-dir subcat bbot arjun waymore

ENV PATH="/opt/pytools/bin:/usr/local/bin:${PATH}"

WORKDIR /app

COPY package*.json ./
RUN npm ci --include=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000

RUN mkdir -p /app/backend/data \
  && npm run build

EXPOSE 3000

CMD ["npm", "start"]
