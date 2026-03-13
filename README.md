# Smart Domain Detector

<p align="center">
  <img src="images/1.png" alt="Smart Domain Detector logo" width="760" />
</p>

<p align="center">
  <strong>Smart Domain Detector</strong> is a Docker-first reconnaissance and exposure analysis platform for SOC teams, security analysts, and validation workflows.
</p>

<p align="center">
  🌐 Passive discovery • 🔎 Live validation • 🕰️ Historical expansion • 🧠 Target intelligence • 📊 Exportable reporting
</p>

## Project overview

Smart Domain Detector combines the work that usually gets split across many separate tools and long manual review steps:

- ⚡ Discover subdomains from multiple passive sources
- 🧭 Resolve and validate live hosts with DNS and HTTP probing
- 🗂️ Expand archived and live URLs with focused crawling
- 🚨 Detect sensitive files, auth portals, VPN surfaces, API docs, and exposure patterns
- 🧠 Build target intelligence with IP ownership, SSL/TLS, owner/contact, mail, and NS data
- 🧾 Save scan history locally and export clean Excel reports for follow-up analysis

## Screenshots

### Live scan workflow

Track live progress, engine output, and the tool checklist while the scan is still running.

![Live scan activity](images/2.jpg)

### Tool health timeline

Follow the pipeline in order while tools move through `pending`, `running`, `completed`, `partial`, and `skipped` states.

![Tool health timeline](images/7.jpg)

### Analyst metric strip

See risk, URLs scanned, critical findings, live assets, and tracked subdomains at a glance.

![Top metrics](images/8.jpg)

### Findings view

Review prioritized findings with severity, confidence, live/archive state, and source attribution.

![Findings table](images/3.jpg)

### Finding detail drawer

Open a finding to see impact, recommended action, validation notes, evidence, and references.

![Finding detail](images/4.jpg)

### Scan depth and advanced controls

Switch between quick triage, live-focused, full coverage, and depth presets with bounded controls.

![Advanced scan controls](images/5.jpg)

### Per-tool timeout tuning

Tune tool budgets safely with guardrails instead of open-ended numeric inputs.

![Timeout controls](images/6.jpg)

## Key capabilities

### Recon and enrichment

- `subfinder`, `assetfinder`, `findomain`, `amass`, `subcat`
- `crt.sh`, `certspotter`, `BufferOver`, `chaos`
- `dnsx`, `httpx`, `subzy`
- `waybackurls`, `gau`, `katana`, `waymore`, `arjun`
- native live recursion, targeted path checks, robots.txt capture, and SSL/TLS collection

### Detection coverage

- 🔐 Sensitive files and backup artifacts
- 🧱 Admin panels and login/auth surfaces
- 🛡️ VPN and remote-access endpoints
- 🧪 API docs, GraphQL, XML-RPC, redirect and SSRF clues
- 📬 Mail and target infrastructure clues
- 📁 Archive-backed and live-backed findings with evidence

### Reporting

- 📘 Excel export with findings, assets, target intelligence, IP intelligence, artifacts, follow-up targets, and tool health
- 🧷 Source/reference context included for downstream validation
- 🧹 Data organized for later leak checks, nuclei runs, manual review, and reporting

## Docker-first runtime

This project is designed to run through Docker so you avoid most Windows vs WSL vs Linux tool issues.

### Quick start

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. From the project root, run:

```bash
docker compose up --build -d
```

3. Open [http://localhost:3000](http://localhost:3000)

### Windows helper

You can also use:

- `docker-control.bat`

It lets you:

- ▶️ Start the Docker stack
- ⏹️ Stop the Docker stack safely
- 🩺 Check Docker status

## Optional configuration

Copy `.env.example` to `.env` if you want to enable optional sources:

```env
PORT=3000
USE_VITE_DEV=false
PDCP_API_KEY=
BUFFEROVER_API_KEY=
```

- `PDCP_API_KEY`: enables Chaos
- `BUFFEROVER_API_KEY`: enables BufferOver passive DNS enrichment

## Project structure

```text
backend/
  data/                 SQLite scan history
  services/             Recon, analyzer, runtime, persistence services
images/                 README screenshots
public/                 Static assets
src/                    React UI
tests/                  Node test suite
server.ts               Unified API + frontend server
docker-control.bat      Docker start/stop/check helper
Dockerfile              Container runtime
docker-compose.yml      Local Docker orchestration
```

## Development

Install dependencies:

```bash
npm install
```

Run the app in development mode:

```bash
npm run dev
```

Build the frontend:

```bash
npm run build
```

Run type/lint checks:

```bash
npm run lint
```

Run tests:

```bash
npm test
```

## Data persistence

Saved reports are stored in:

- `backend/data/scans.db`

Docker mounts the same folder, so scan history persists across container restarts.

## Tool behavior notes

- ✅ `completed`: tool finished normally
- 🟢 `partial`: tool returned useful results before timeout
- 🟠 `pending`: tool is queued or waiting for its stage
- ⚪ `skipped`: intentionally not used for this scan mode, disabled by config, or missing API setup
- 🔴 `failed`: tool ran but did not return a usable result

Notes:

- External sources can still rate-limit or temporarily fail.
- Some upstream archive services may return `429` or no results for a given host.
- Docker removes most native Windows compatibility friction, but upstream network/provider issues can still happen.

## Troubleshooting

### “Network error” in the browser

If the UI shows a network error:

1. Confirm Docker is still running
2. Confirm the container is healthy:

```bash
docker compose ps
```

3. Check logs:

```bash
docker compose logs --tail=200
```

4. Refresh [http://localhost:3000](http://localhost:3000)

### Tool shows `skipped`

That usually means one of these is true:

- the tool is intentionally disabled for the selected scan mode
- an API key is not configured
- the workflow is prioritizing faster sources first

### Archive source looks weak

Archive providers can be inconsistent across domains. Smart Domain Detector already retries and focuses on higher-value hosts first, but some targets genuinely return less historical data.

## GitHub-ready notes

- ✅ Source only: generated logs, databases, caches, and build output are ignored
- ✅ Docker-first install path documented
- ✅ Screenshots included
- ✅ Saved reports persist locally
- ✅ Exported reports are structured for downstream verification and reporting

---

## Version

**Smart Domain Detector v1.0**

© 2026 Professional project by [github.com/smartboy223](https://github.com/smartboy223)

## Contributions

Contributions, improvements, and future developments are welcome.
