"""
Configuration for the PyPI → GitHub release monitor.
"""
import os

# ── Feed ────────────────────────────────────────────────────────────────────
PYPI_RSS_URL = "https://pypi.org/rss/updates.xml"
PYPI_JSON_API = "https://pypi.org/pypi/{package}/json"
PYPI_VERSION_API = "https://pypi.org/pypi/{package}/{version}/json"

# ── GitHub ──────────────────────────────────────────────────────────────────
# Set GITHUB_TOKEN env var for higher rate limits (5 000 req/h vs 60 req/h).
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"

# ── Polling ─────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS = 120          # how often to re-fetch the RSS feed
GRACE_PERIOD_HOURS = 48              # delay before flagging (avoid false positives)
NUM_WORKERS = 4                      # concurrent analysis workers

# ── Rate-limiting (PyPI + GitHub) ───────────────────────────────────────────
REQUEST_DELAY_SECONDS = 0.2          # polite delay between HTTP calls (lower for concurrency)

# ── Re-verification ─────────────────────────────────────────────────────────
REVERIFY_MIN_AGE_SECONDS = 1800      # re-check flagged entries older than this (30 min)
REVERIFY_EVERY_N_POLLS = 3           # run re-verification every N poll cycles

# ── Confidence thresholds ───────────────────────────────────────────────────
CONFIDENCE_CRITICAL = 70             # score >= this → CRITICAL severity
CONFIDENCE_HIGH = 50                 # score >= this → HIGH severity
CONFIDENCE_MEDIUM = 30               # score >= this → MEDIUM severity

# ── Risk signal thresholds ──────────────────────────────────────────────────
RAPID_PUBLISH_MINUTES = 30           # version gap shorter than this is suspicious
HIGH_VALUE_DOWNLOADS = 50000         # monthly downloads above this is high-value target

# ── Logging / Output ───────────────────────────────────────────────────────
LOG_FILE = "monitor.log"
FLAGGED_OUTPUT_FILE = "flagged_packages.json"   # legacy, kept for migration

# ── Database ────────────────────────────────────────────────────────────────
DB_FILE = "monitor.db"                          # single SQLite database

# ── State persistence (legacy JSON – migrated to DB on first run) ───────────
SCAN_STATE_FILE = "scan_state.json"
FEED_SEEN_FILE = "feed_seen.json"

# ── Trusted publishers ──────────────────────────────────────────────────────
TRUSTED_PUBLISHERS_FILE = "trusted_publishers.json"  # legacy, migrated to DB
