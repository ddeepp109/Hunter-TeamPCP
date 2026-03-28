"""
SQLite persistence layer for the PyPI ↔ GitHub monitor.

All application state is stored in a single ``monitor.db`` file so that
restarts, crashes, and upgrades never lose data.

Tables:
  flagged_packages  – packages flagged for analyst review
  scans             – recent scan log (last 500)
  feed_seen         – pubDate dedup for the RSS poller
  trusted_publishers– known-good publisher allow-list
  settings          – key/value runtime config (poll_interval, workers)
  logs              – in-app log entries (last 2000)
"""

import json
import logging
import os
import sqlite3
import threading

from . import config
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Project root is one level above hunter/
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_PATH = os.environ.get("DB_PATH",
         os.path.join(_PROJECT_ROOT, "monitor.db"))

# Ensure the DB directory exists (Railway/Docker may not pre-create it)
os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

# One connection per thread (SQLite requirement)
_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        # Verify the connection is still usable
        try:
            conn.execute("SELECT 1")
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            conn = None
            _local.conn = None
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=15)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        _local.conn = conn
    return conn


@contextmanager
def _cursor():
    """Yield a cursor that auto-commits on success."""
    conn = _get_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ── Schema creation ─────────────────────────────────────────────────────────

def init_db():
    """Create tables if they don't exist.  Safe to call on every startup."""
    with _cursor() as cur:
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS flagged_packages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            version         TEXT NOT NULL,
            severity        TEXT NOT NULL,
            reason          TEXT NOT NULL DEFAULT '',
            pypi_link       TEXT NOT NULL DEFAULT '',
            github_owner    TEXT,
            github_repo     TEXT,
            author          TEXT DEFAULT '',
            author_email    TEXT DEFAULT '',
            summary         TEXT DEFAULT '',
            flagged_at      TEXT NOT NULL,
            verification    TEXT,          -- JSON blob
            pypi_version    TEXT DEFAULT '',
            github_releases TEXT,          -- JSON array
            github_tags     TEXT,          -- JSON array
            risk_signals    TEXT,          -- JSON array
            confidence_score INTEGER DEFAULT 0,
            monthly_downloads INTEGER,
            rapid_publish_gap REAL,
            yanked_versions TEXT,          -- JSON array
            UNIQUE(name, version)
        );

        CREATE INDEX IF NOT EXISTS idx_flagged_name ON flagged_packages(name);
        CREATE INDEX IF NOT EXISTS idx_flagged_severity ON flagged_packages(severity);
        CREATE INDEX IF NOT EXISTS idx_flagged_confidence ON flagged_packages(confidence_score DESC);

        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL,
            version   TEXT NOT NULL,
            flagged   INTEGER NOT NULL DEFAULT 0,
            scanned_at TEXT NOT NULL,
            github_owner  TEXT DEFAULT '',
            github_repo   TEXT DEFAULT '',
            github_releases TEXT DEFAULT '',
            pypi_link TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scanned_at DESC);

        CREATE TABLE IF NOT EXISTS feed_seen (
            key       TEXT PRIMARY KEY,      -- "name==version"
            pub_date  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS trusted_publishers (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            note TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT NOT NULL,
            message    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS visitors (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT NOT NULL,
            path       TEXT NOT NULL DEFAULT '/',
            user_agent TEXT DEFAULT '',
            visited_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_visitors_time ON visitors(visited_at DESC);        """)

    # Migrate: add columns to scans if they don't exist yet (existing DBs)
    try:
        with _cursor() as cur:
            cols = {r[1] for r in cur.execute("PRAGMA table_info(scans)").fetchall()}
            for col, default in [
                ("github_owner", "''"), ("github_repo", "''"),
                ("github_releases", "''"), ("pypi_link", "''"),
            ]:
                if col not in cols:
                    cur.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT DEFAULT {default}")
    except Exception:
        pass

    logger.info("Database initialised at %s", DB_PATH)


# ── Flagged packages ────────────────────────────────────────────────────────

def _flag_to_row(d: dict) -> dict:
    """Normalise a FlaggedPackage dict for DB insertion (JSON-encode lists)."""
    row = dict(d)
    for col in ("verification", "github_releases", "github_tags",
                "risk_signals", "yanked_versions"):
        val = row.get(col)
        if val is not None and not isinstance(val, str):
            row[col] = json.dumps(val, default=str)
    return row


def _row_to_flag(row: sqlite3.Row) -> dict:
    """Convert a DB row back to the dict format the UI expects."""
    d = dict(row)
    for col in ("verification", "github_releases", "github_tags",
                "risk_signals", "yanked_versions"):
        val = d.get(col)
        if val and isinstance(val, str):
            try:
                d[col] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                pass
    return d


def upsert_flagged(flag_dict: dict) -> None:
    """Insert or update a flagged package (dedup by name+version).

    If a row for the same (name, version) already exists, it is updated
    only when the new severity is equal or higher.
    """
    row = _flag_to_row(flag_dict)
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    with _cursor() as cur:
        cur.execute(
            "SELECT severity FROM flagged_packages WHERE name=? AND version=?",
            (row["name"], row["version"]),
        )
        existing = cur.fetchone()
        if existing:
            old_sev = sev_order.get(existing["severity"], 0)
            new_sev = sev_order.get(row.get("severity", ""), 0)
            if new_sev >= old_sev:
                cur.execute("""
                    UPDATE flagged_packages SET
                        severity=?, reason=?, pypi_link=?,
                        github_owner=?, github_repo=?,
                        author=?, author_email=?, summary=?,
                        flagged_at=?, verification=?,
                        pypi_version=?, github_releases=?, github_tags=?,
                        risk_signals=?, confidence_score=?,
                        monthly_downloads=?, rapid_publish_gap=?,
                        yanked_versions=?
                    WHERE name=? AND version=?
                """, (
                    row.get("severity"), row.get("reason"), row.get("pypi_link"),
                    row.get("github_owner"), row.get("github_repo"),
                    row.get("author"), row.get("author_email"), row.get("summary"),
                    row.get("flagged_at"), row.get("verification"),
                    row.get("pypi_version"), row.get("github_releases"),
                    row.get("github_tags"), row.get("risk_signals"),
                    row.get("confidence_score", 0),
                    row.get("monthly_downloads"), row.get("rapid_publish_gap"),
                    row.get("yanked_versions"),
                    row["name"], row["version"],
                ))
        else:
            cur.execute("""
                INSERT INTO flagged_packages (
                    name, version, severity, reason, pypi_link,
                    github_owner, github_repo,
                    author, author_email, summary,
                    flagged_at, verification,
                    pypi_version, github_releases, github_tags,
                    risk_signals, confidence_score,
                    monthly_downloads, rapid_publish_gap, yanked_versions
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                row.get("name"), row.get("version"),
                row.get("severity"), row.get("reason"), row.get("pypi_link"),
                row.get("github_owner"), row.get("github_repo"),
                row.get("author"), row.get("author_email"), row.get("summary"),
                row.get("flagged_at"), row.get("verification"),
                row.get("pypi_version"), row.get("github_releases"),
                row.get("github_tags"), row.get("risk_signals"),
                row.get("confidence_score", 0),
                row.get("monthly_downloads"), row.get("rapid_publish_gap"),
                row.get("yanked_versions"),
            ))


def get_all_flagged(severity: str = "", search: str = "") -> List[dict]:
    """Return all flagged packages, ordered by confidence desc."""
    clauses = []
    params: list = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if search:
        clauses.append("(name LIKE ? OR author LIKE ? OR reason LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term, term])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM flagged_packages {where} ORDER BY confidence_score DESC",
            params,
        )
        return [_row_to_flag(r) for r in cur.fetchall()]


def get_flagged_count() -> int:
    with _cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM flagged_packages")
        return cur.fetchone()[0]


def get_severity_counts() -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    with _cursor() as cur:
        cur.execute("SELECT severity, COUNT(*) FROM flagged_packages GROUP BY severity")
        for row in cur.fetchall():
            counts[row[0]] = row[1]
    return counts


def delete_flagged(name: str, version: str) -> bool:
    with _cursor() as cur:
        cur.execute(
            "DELETE FROM flagged_packages WHERE name=? AND version=?",
            (name, version),
        )
        return cur.rowcount > 0


def delete_flagged_batch(keys: List[Tuple[str, str]]) -> int:
    """Remove multiple flagged entries by (name, version) pairs."""
    removed = 0
    with _cursor() as cur:
        for name, version in keys:
            cur.execute(
                "DELETE FROM flagged_packages WHERE name=? AND version=?",
                (name, version),
            )
            removed += cur.rowcount
    return removed


def get_flagged_keys() -> set:
    """Return set of (name, version) tuples for all flagged packages."""
    with _cursor() as cur:
        cur.execute("SELECT name, version FROM flagged_packages")
        return {(r["name"], r["version"]) for r in cur.fetchall()}


def get_flagged_for_reverify(min_age_seconds: int = 3600) -> List[dict]:
    """Return flagged packages older than `min_age_seconds` for re-verification."""
    with _cursor() as cur:
        cur.execute(
            """SELECT * FROM flagged_packages
               WHERE flagged_at <= datetime('now', ? || ' seconds')
               ORDER BY confidence_score DESC""",
            (f"-{min_age_seconds}",),
        )
        return [_row_to_flag(r) for r in cur.fetchall()]


# ── Scans ───────────────────────────────────────────────────────────────────

def add_scan(name: str, version: str, flagged: bool, *,
             github_owner: str = "", github_repo: str = "",
             github_releases: Optional[List[str]] = None,
             pypi_link: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    gh_rels = json.dumps(github_releases or [])
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO scans (name, version, flagged, scanned_at, "
            "github_owner, github_repo, github_releases, pypi_link) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (name, version, int(flagged), ts,
             github_owner or "", github_repo or "", gh_rels, pypi_link or ""),
        )
        # Keep only last 500 entries
        cur.execute("""
            DELETE FROM scans WHERE id NOT IN (
                SELECT id FROM scans ORDER BY id DESC LIMIT 500
            )
        """)


def get_recent_scans(limit: int = 200) -> List[dict]:
    with _cursor() as cur:
        cur.execute(
            "SELECT name, version, flagged, scanned_at as time, "
            "github_owner, github_repo, github_releases, pypi_link "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = []
        for r in cur.fetchall():
            gh_rels = []
            try:
                raw = r["github_releases"]
                if raw:
                    gh_rels = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
            rows.append({
                "name": r["name"],
                "version": r["version"],
                "flagged": bool(r["flagged"]),
                "time": r["time"],
                "github_owner": r["github_owner"] or "",
                "github_repo": r["github_repo"] or "",
                "github_releases": gh_rels,
                "pypi_link": r["pypi_link"] or "",
            })
        return rows


def get_total_scanned() -> int:
    with _cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM scans")
        return cur.fetchone()[0]


# ── Feed seen (pubDate dedup) ───────────────────────────────────────────────

def get_feed_seen() -> Dict[str, str]:
    """Return all seen feed entries as {key: pub_date_iso}."""
    with _cursor() as cur:
        cur.execute("SELECT key, pub_date FROM feed_seen")
        return {r["key"]: r["pub_date"] for r in cur.fetchall()}


def upsert_feed_seen(key: str, pub_date: str) -> None:
    with _cursor() as cur:
        cur.execute(
            "INSERT OR REPLACE INTO feed_seen (key, pub_date) VALUES (?,?)",
            (key, pub_date),
        )


def upsert_feed_seen_batch(entries: Dict[str, str]) -> None:
    """Bulk upsert feed_seen entries."""
    with _cursor() as cur:
        cur.executemany(
            "INSERT OR REPLACE INTO feed_seen (key, pub_date) VALUES (?,?)",
            list(entries.items()),
        )


# ── Trusted publishers ──────────────────────────────────────────────────────

def get_trusted_publishers() -> List[dict]:
    with _cursor() as cur:
        cur.execute("SELECT name, note FROM trusted_publishers ORDER BY name")
        return [dict(r) for r in cur.fetchall()]


def add_trusted_publisher(name: str, note: str = "") -> bool:
    """Add a trusted publisher. Returns False if already exists."""
    try:
        with _cursor() as cur:
            cur.execute(
                "INSERT INTO trusted_publishers (name, note) VALUES (?,?)",
                (name.strip(), note.strip()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def remove_trusted_publisher(name: str) -> bool:
    with _cursor() as cur:
        cur.execute(
            "DELETE FROM trusted_publishers WHERE name=? COLLATE NOCASE",
            (name,),
        )
        return cur.rowcount > 0


def is_trusted_publisher(name: str) -> bool:
    with _cursor() as cur:
        cur.execute(
            "SELECT 1 FROM trusted_publishers WHERE name=? COLLATE NOCASE",
            (name,),
        )
        return cur.fetchone() is not None


# ── Settings ────────────────────────────────────────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    with _cursor() as cur:
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with _cursor() as cur:
        cur.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)",
            (key, value),
        )


def get_setting_int(key: str, default: int = 0) -> int:
    val = get_setting(key)
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


# ── Logs ────────────────────────────────────────────────────────────────────

def add_log(message: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO logs (timestamp, message) VALUES (?,?)",
            (ts, message),
        )
        # Keep only last 2000 entries
        cur.execute("""
            DELETE FROM logs WHERE id NOT IN (
                SELECT id FROM logs ORDER BY id DESC LIMIT 2000
            )
        """)


def get_logs(limit: int = 500) -> List[str]:
    """Return formatted log lines, newest first."""
    with _cursor() as cur:
        cur.execute(
            "SELECT timestamp, message FROM logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [f"[{r['timestamp']}]  {r['message']}" for r in cur.fetchall()]


def hard_reset():
    """Drop all data tables and recreate them.  Settings are preserved."""
    with _cursor() as cur:
        cur.executescript("""
            DELETE FROM flagged_packages;
            DELETE FROM scans;
            DELETE FROM feed_seen;
            DELETE FROM logs;
            DELETE FROM visitors;
        """)
    logger.info("Hard reset: all scan data cleared.")


# ── Visitors ────────────────────────────────────────────────────────────────

def record_visit(ip: str, path: str, user_agent: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _cursor() as cur:
        cur.execute(
            "INSERT INTO visitors (ip, path, user_agent, visited_at) VALUES (?,?,?,?)",
            (ip, path, user_agent, ts),
        )
        # Keep only last 5000 entries
        cur.execute("""
            DELETE FROM visitors WHERE id NOT IN (
                SELECT id FROM visitors ORDER BY id DESC LIMIT 5000
            )
        """)


def get_visitors(limit: int = 200) -> List[dict]:
    with _cursor() as cur:
        cur.execute(
            "SELECT ip, path, user_agent, visited_at FROM visitors ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_online_visitors(minutes: int = 5) -> List[dict]:
    """Return distinct IPs that visited in the last N minutes."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    with _cursor() as cur:
        cur.execute("""
            SELECT ip, MAX(visited_at) as last_seen,
                   MAX(path) as last_path, MAX(user_agent) as user_agent
            FROM visitors
            WHERE visited_at >= ?
            GROUP BY ip
            ORDER BY last_seen DESC
        """, (cutoff,))
        return [dict(r) for r in cur.fetchall()]


def get_visitor_stats() -> dict:
    with _cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM visitors")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT ip) FROM visitors")
        unique = cur.fetchone()[0]
        return {"total_visits": total, "unique_visitors": unique}


# ── Migration: import old JSON files into DB ────────────────────────────────

def migrate_from_json():
    """One-time import of existing JSON files into the database.

    Runs on startup; skips files that don't exist or are already imported.
    """
    base = os.path.dirname(os.path.abspath(__file__))

    # 1. flagged_packages.json
    fp = os.path.join(base, "flagged_packages.json")
    if os.path.exists(fp):
        try:
            with open(fp) as fh:
                data = json.load(fh)
            for d in data:
                upsert_flagged(d)
            logger.info("Migrated %d flagged packages from JSON", len(data))
            os.rename(fp, fp + ".bak")
        except Exception as exc:
            logger.warning("Failed migrating flagged_packages.json: %s", exc)

    # 2. feed_seen.json
    fs = os.path.join(base, "feed_seen.json")
    if os.path.exists(fs):
        try:
            with open(fs) as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                upsert_feed_seen_batch(data)
                logger.info("Migrated %d feed_seen entries from JSON", len(data))
            os.rename(fs, fs + ".bak")
        except Exception as exc:
            logger.warning("Failed migrating feed_seen.json: %s", exc)

    # 3. scan_state.json
    ss = os.path.join(base, "scan_state.json")
    if os.path.exists(ss):
        try:
            with open(ss) as fh:
                data = json.load(fh)
            if "started_at" in data:
                set_setting("started_at", str(data["started_at"]))
            if "last_poll" in data:
                set_setting("last_poll", str(data["last_poll"]))
            for scan in data.get("recent_scans", []):
                add_scan(scan["name"], scan["version"], scan.get("flagged", False))
            logger.info("Migrated scan state from JSON")
            os.rename(ss, ss + ".bak")
        except Exception as exc:
            logger.warning("Failed migrating scan_state.json: %s", exc)

    # 4. trusted_publishers.json
    tp = os.path.join(base, "trusted_publishers.json")
    if os.path.exists(tp):
        try:
            with open(tp) as fh:
                data = json.load(fh)
            for entry in data:
                add_trusted_publisher(entry.get("name", ""), entry.get("note", ""))
            logger.info("Migrated %d trusted publishers from JSON", len(data))
            os.rename(tp, tp + ".bak")
        except Exception as exc:
            logger.warning("Failed migrating trusted_publishers.json: %s", exc)
