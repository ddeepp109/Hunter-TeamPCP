# PyPI ↔ GitHub Release Monitor

A detection pipeline that monitors PyPI package publications and flags packages
that lack a corresponding GitHub release or tag — behaviour associated with
supply-chain attacks like **TeamPCP**.

## How It Works

```
PyPI RSS Feed ──► Fetch Metadata (JSON API) ──► Resolve GitHub Repo
                                                       │
                                          ┌────────────┘
                                          ▼
                                   Check Releases/Tags
                                          │
                                          ▼
                                   Classify & Flag
                                          │
                                  ┌───────┴───────┐
                                  ▼               ▼
                           flagged_packages.json  Console + Log
```

### Severity Levels

| Severity   | Meaning |
|------------|---------|
| **CRITICAL** | GitHub repo exists but published version has **no** matching release or tag |
| **HIGH**     | PyPI metadata references a GitHub repo that doesn't exist or is private |
| **MEDIUM**   | No GitHub repository linked in PyPI metadata at all |
| **LOW**      | Within the grace period (< 48 h) — may appear on GitHub soon |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Recommended) Set a GitHub token for higher API rate limits
export GITHUB_TOKEN="ghp_..."

# 3. Single-scan mode – analyse the current RSS feed and exit
python monitor.py --once

# 4. Continuous monitoring mode
python monitor.py

# 5. Custom poll interval (seconds)
python monitor.py --interval 60

# 6. Verbose / debug logging
python monitor.py --once -v
```

## Configuration

Edit **config.py** to tune:

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL_SECONDS` | 120 | Seconds between RSS feed polls |
| `GRACE_PERIOD_HOURS` | 48 | Hours after publication before raising severity above LOW |
| `REQUEST_DELAY_SECONDS` | 1.0 | Polite delay between HTTP calls |
| `GITHUB_TOKEN` | `""` (env) | GitHub personal access token for 5 000 req/h |
| `TRUSTED_PUBLISHERS_FILE` | `trusted_publishers.json` | Allow-list of known-safe packages |

## Trusted Publishers

Edit **trusted_publishers.json** to suppress alerts for well-known packages
that intentionally don't follow standard GitHub release practices:

```json
[
  { "name": "boto3", "note": "AWS SDK – releases via internal process" }
]
```

## Output

- **Console** – colour-coded severity banners printed in real time.
- **monitor.log** – full structured log file.
- **flagged_packages.json** – machine-readable list of all flagged packages with
  metadata, suitable for feeding into SIEM or ticketing systems.

## Safety

- **No packages are downloaded.** The tool only reads PyPI JSON metadata and the
  RSS feed — it never fetches `.tar.gz` / `.whl` files.
- Uses only public APIs (PyPI JSON API + GitHub REST API).
- Respects rate limits with configurable request delays.

## Project Structure

```
├── config.py             # All tunables
├── pypi_feed.py          # RSS feed fetcher + poller
├── github_resolver.py    # Resolve GitHub owner/repo from PyPI metadata
├── github_checker.py     # Verify releases & tags on GitHub
├── flagger.py            # Classification engine + persistence
├── monitor.py            # CLI entry point & orchestration
├── trusted_publishers.json
├── requirements.txt
└── README.md
```
