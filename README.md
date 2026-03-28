<div align="center">

# 🎯 Hunter TeamPCP

**Real-time PyPI supply-chain threat detection platform**

Monitors every PyPI package publication and flags versions that appear on PyPI
without a corresponding GitHub release or tag — the exact attack pattern used
in the [TeamPCP campaign](https://www.endorlabs.com/learn/teampcp-a-growing-threat-to-the-pypi-ecosystem) against packages like `telnyx` and `litellm`.

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Deploy: Railway](https://img.shields.io/badge/deploy-Railway-blueviolet.svg)](https://railway.app/)

</div>

---

## Overview

Attackers who steal a PyPI API token can publish malicious versions **directly** to PyPI without ever touching the project's GitHub repository. Hunter TeamPCP catches that discrepancy in real time by continuously polling the PyPI RSS feed and cross-referencing every new release against the project's GitHub releases and tags.

### Detection Pipeline

```
  ┌─────────────────┐     ┌───────────────────┐     ┌──────────────────┐
  │  PyPI RSS Feed   │────▶│  Resolve GitHub    │────▶│  Verify Release  │
  │  (120 s poll)    │     │  Repo from Metadata│     │  Tags on GitHub  │
  └─────────────────┘     └───────────────────┘     └────────┬─────────┘
                                                              │
                                                              ▼
                                                    ┌──────────────────┐
                                                    │  Classify & Score│
                                                    │  (0–100 conf.)   │
                                                    └────────┬─────────┘
                                                              │
                                          ┌───────────────────┼───────────────────┐
                                          ▼                   ▼                   ▼
                                   ┌────────────┐    ┌──────────────┐    ┌──────────────┐
                                   │  Web UI     │    │  SQLite DB   │    │  Structured  │
                                   │  Dashboard  │    │  Persistence │    │  Logs        │
                                   └────────────┘    └──────────────┘    └──────────────┘
```

### Risk Signals

The confidence scoring model (0–100) evaluates multiple threat indicators:

| Signal | Score Contribution | Description |
|---|---|---|
| **Version mismatch** | +30 base | PyPI version has no matching GitHub release/tag |
| **Rapid publish** | +25 | Published < 30 min after previous version |
| **Very rapid** | +5 | Published < 5 min (automated attack) |
| **Yanked neighbors** | +15 | Adjacent versions on PyPI are yanked |
| **High-value target** | +20 / +30 | Package has > 50K / > 500K monthly downloads |

### Severity Classification

| Severity | Meaning |
|---|---|
| **CRITICAL** | GitHub repo exists, but the published version has **no** matching release or tag |
| **HIGH** | PyPI metadata references a GitHub repo that doesn't exist or is private |
| **LOW** | Within the grace period — release may appear on GitHub soon |

### False-Positive Reduction

The system avoids common false positives through:

- **PEP 440 ↔ semver mapping** — `5.0.0rc16` matches `v5.0.0-rc16`
- **Monorepo awareness** — skips repos with unrelated version series (e.g. DataDog `ddev-v14.x` vs PyPI `37.x`)
- **Version comparison** — skips when GitHub is ahead of PyPI
- **Dev/pre-release filtering** — ignores alpha, beta, dev, and RC versions
- **No-release repos** — skips projects that don't use GitHub releases at all
- **Deduplication** — each (name, version) pair is only flagged once
- **Auto re-verification** — flags are re-checked after 30 min and cleared if the release appears

---

## Quick Start

### Prerequisites

- Python 3.10+
- A GitHub personal access token (for 5,000 req/hr vs 60 req/hr unauthenticated)

### Local Development

```bash
# Clone the repository
git clone https://github.com/ddeepp109/Hunter-TeamPCP.git
cd Hunter-TeamPCP

# Create virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Set GitHub token (recommended)
export GITHUB_TOKEN="ghp_..."

# Start the web dashboard (port 8050)
python -m hunter.webapp
```

Open **http://localhost:8050** to access the dashboard.

### CLI Mode

```bash
# Single scan — analyse current RSS feed and exit
python -m hunter.monitor --once

# Continuous monitoring
python -m hunter.monitor

# Custom poll interval (seconds)
python -m hunter.monitor --interval 60

# Verbose logging
python -m hunter.monitor --once -v
```

---

## Web Dashboard

The built-in Flask dashboard provides full visibility into the detection pipeline:

| Page | Description |
|---|---|
| **Dashboard** | KPI cards, real-time scan feed, monitor controls, latest flagged packages |
| **Queue** | Live view of concurrent workers, priority queue, batch progress |
| **Flagged** | All flagged packages with confidence scores, severity, risk signals |
| **Logs** | Real-time structured log stream |
| **Settings** | Poll interval, worker count, trusted publishers, hard reset |

### Key Features

- **Real-time updates** — auto-refreshing every 4 seconds
- **Concurrent pipeline** — configurable thread pool (1–16 workers)
- **Confidence scoring** — 0–100 risk score per flagged package
- **Persistent storage** — SQLite with WAL mode, survives restarts
- **Trusted publishers** — allowlist packages that don't follow standard release practices
- **Hard reset** — wipe all data and start fresh from Settings
- **First-time onboarding** — guided walkthrough of the detection pipeline

---

## Configuration

All settings are configurable via **`config.py`** or the web UI:

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL_SECONDS` | `120` | Seconds between RSS feed polls |
| `GRACE_PERIOD_HOURS` | `48` | Hours before raising severity above LOW |
| `NUM_WORKERS` | `4` | Concurrent analysis threads |
| `REQUEST_DELAY_SECONDS` | `0.2` | Rate-limit delay between API calls |
| `GITHUB_TOKEN` | env `GITHUB_TOKEN` | GitHub PAT for higher rate limits |
| `DB_FILE` | `monitor.db` | SQLite database file |

---

## Deployment

### Docker

```bash
docker build -t hunter-teampcp .
docker run -p 8080:8080 \
  -e GITHUB_TOKEN="ghp_..." \
  -v hunter-data:/app/data \
  hunter-teampcp
```

### Railway (Recommended)

1. Connect your GitHub repo to [Railway](https://railway.app/)
2. Set the `GITHUB_TOKEN` environment variable
3. Railway auto-detects the Dockerfile and deploys

The app reads `$PORT` at runtime and stores data in `/app/data/monitor.db`.

---

## Architecture

```
Hunter-TeamPCP/
├── hunter/                    # Core application package
│   ├── __init__.py            # Package version & metadata
│   ├── config.py              # All configuration variables
│   ├── db.py                  # SQLite persistence layer (WAL mode, thread-safe)
│   ├── flagger.py             # Classification engine + severity assignment
│   ├── github_checker.py      # Verifies releases & tags with tag pattern matching
│   ├── github_resolver.py     # Resolves GitHub owner/repo from PyPI metadata
│   ├── pipeline.py            # Concurrent processing engine (ThreadPoolExecutor)
│   ├── pypi_analyzer.py       # Risk signal analysis + confidence scoring
│   ├── pypi_feed.py           # RSS feed poller with pubDate deduplication
│   ├── webapp.py              # Flask app + routes + background monitor thread
│   └── monitor.py             # CLI entry point
├── templates/                 # Jinja2 web templates
│   ├── layout.html            # Base template with sidebar + TrendAI branding
│   ├── dashboard.html         # Main dashboard with KPIs and scan feed
│   ├── flagged.html           # Flagged packages table
│   ├── queue.html             # Worker queue live view
│   ├── logs.html              # Structured log viewer
│   └── settings.html          # Configuration panel
├── Dockerfile                 # Production container (Python 3.13-slim + Gunicorn)
├── fly.toml                   # Fly.io deployment config
├── deploy.sh                  # Deployment helper script
├── requirements.txt           # Python dependencies
├── README.md
└── .gitignore
```

---

## Safety & Privacy

- **No packages are ever downloaded.** Only PyPI JSON metadata and the RSS feed are read — no `.tar.gz` or `.whl` files are fetched.
- Uses only public APIs: PyPI JSON API and GitHub REST API.
- Respects rate limits with configurable request delays.
- SQLite database stays local — no data is sent to external services.

---

## License

MIT

---

<div align="center">
  <sub>Built by the <strong>TrendAI ZDI Threat Hunter Team</strong></sub>
</div>
