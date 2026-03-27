"""
PyPI ↔ GitHub Release Monitor – Web UI (24/7 pipeline).

Run:
    python webapp.py
    # Visit http://127.0.0.1:5000
"""

import json
import logging
import os
import threading
import time
from collections import deque
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template, request

import config
from flagger import FlaggedPackage, classify, save_flagged, _is_dev_version
from github_checker import verify_version
from github_resolver import fetch_pypi_metadata, find_github_repo
from pypi_feed import FeedPoller, PackageUpdate

# ── Flask app ───────────────────────────────────────────────────────────────

app = Flask(__name__)

# ── In-memory state shared between monitor thread & web routes ──────────────

class MonitorState:
    """Thread-safe shared state for the monitoring pipeline."""

    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.started_at: str | None = None
        self.last_poll: str | None = None
        self.next_poll: str | None = None
        self.total_scanned = 0
        self.total_flagged = 0
        self.flagged: list[dict] = []          # newest first
        self.recent_scans: deque = deque(maxlen=200)  # last 200 scanned
        self.severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        self.log_lines: deque = deque(maxlen=500)
        self.poll_interval = config.POLL_INTERVAL_SECONDS
        self._stop_event = threading.Event()

    # --- helpers ---

    def add_log(self, msg: str):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            self.log_lines.appendleft(f"[{ts}]  {msg}")

    def add_flagged(self, flag: FlaggedPackage):
        d = asdict(flag)
        with self.lock:
            # Dedup: don't add if same (name, version) already exists
            key = (flag.name, flag.version)
            if any((f.get("name"), f.get("version")) == key for f in self.flagged):
                return
            self.flagged.insert(0, d)
            self.total_flagged += 1
            sev = flag.severity
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1

    def add_scan(self, name: str, version: str, flagged: bool):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            self.total_scanned += 1
            self.recent_scans.appendleft({
                "name": name,
                "version": version,
                "flagged": flagged,
                "time": ts,
            })

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "running": self.running,
                "started_at": self.started_at,
                "last_poll": self.last_poll,
                "next_poll": self.next_poll,
                "total_scanned": self.total_scanned,
                "total_flagged": self.total_flagged,
                "severity_counts": dict(self.severity_counts),
                "poll_interval": self.poll_interval,
            }


state = MonitorState()

# ── Load persisted flagged packages on startup ──────────────────────────────

def _load_persisted_flags():
    path = config.FLAGGED_OUTPUT_FILE
    if not os.path.exists(path):
        return
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        with state.lock:
            state.flagged = list(reversed(data))  # newest first
            state.total_flagged = len(data)
            for d in data:
                sev = d.get("severity", "")
                if sev in state.severity_counts:
                    state.severity_counts[sev] += 1
    except Exception:
        pass


# ── Background monitor thread ──────────────────────────────────────────────

def _analyse_one(update: PackageUpdate) -> FlaggedPackage | None:
    """Run the full pipeline for a single package (same as monitor.py)."""
    state.add_log(f"Analysing {update.name} {update.version} …")

    meta = fetch_pypi_metadata(update.name)
    if meta is None:
        state.add_log(f"  ⚠ Could not fetch metadata for {update.name}")
        return None

    gh = find_github_repo(meta)
    verification = None

    if gh:
        owner, repo = gh
        state.add_log(f"  GitHub repo: {owner}/{repo}")
        verification = verify_version(update.name, update.version, owner, repo)
    else:
        state.add_log(f"  No GitHub repo found for {update.name}")

    flag = classify(
        package_name=update.name,
        version=update.version,
        pypi_link=update.link,
        meta=meta,
        github_repo_found=gh is not None,
        verification=verification,
        pub_date=update.pub_date,
    )
    return flag


def _monitor_loop():
    """Continuous polling loop that runs in a daemon thread."""
    poller = FeedPoller()
    state.add_log("Monitor thread started.")
    state.started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    poll_count = 0

    while not state._stop_event.is_set():
        poll_count += 1
        with state.lock:
            state.running = True
            state.last_poll = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        state.add_log("Polling PyPI RSS feed …")
        updates = poller.poll_once()

        # Build set of already-flagged (name, version) to avoid duplicates
        with state.lock:
            already_flagged = {
                (d.get("name", ""), d.get("version", ""))
                for d in state.flagged
            }

        if updates:
            state.add_log(f"Found {len(updates)} new updates.")
            batch_flagged: list[FlaggedPackage] = []

            for u in updates:
                if state._stop_event.is_set():
                    break
                # Skip if already flagged for this exact version
                if (u.name, u.version) in already_flagged:
                    state.add_scan(u.name, u.version, True)
                    state.add_log(f"  ↺ {u.name} {u.version} – already flagged, skipping re-check")
                    continue
                try:
                    flag = _analyse_one(u)
                    was_flagged = flag is not None
                    state.add_scan(u.name, u.version, was_flagged)
                    if flag:
                        batch_flagged.append(flag)
                        state.add_flagged(flag)
                        state.add_log(
                            f"  🚩 [{flag.severity}] {flag.name} {flag.version} – {flag.reason[:80]}"
                        )
                    else:
                        state.add_log(f"  ✓ {u.name} {u.version} – clean")
                except Exception as exc:
                    state.add_log(f"  ✗ Error analysing {u.name}: {exc}")

            if batch_flagged:
                save_flagged(batch_flagged)
                state.add_log(f"Batch done – {len(batch_flagged)} flagged out of {len(updates)}.")
            else:
                state.add_log(f"Batch done – {len(updates)} packages, none flagged.")
        else:
            state.add_log("No new updates in feed.")

        # Re-verify flagged packages that are >= 1 hour old
        _reverify_stale_flags()

        # Calculate next poll time
        next_time = datetime.now(timezone.utc).timestamp() + state.poll_interval
        with state.lock:
            state.next_poll = datetime.fromtimestamp(
                next_time, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Sleep in small increments so we can stop quickly
        for _ in range(int(state.poll_interval)):
            if state._stop_event.is_set():
                break
            time.sleep(1)

    with state.lock:
        state.running = False
    state.add_log("Monitor thread stopped.")


def _reverify_stale_flags():
    """Re-check flagged packages that are >= 1 hour old.

    This handles delayed GitHub releases: maintainers who publish to
    PyPI first and tag GitHub later.  Only entries whose flagged_at
    timestamp is at least 1 hour ago are re-verified.

    Removes flags when:
    - The GitHub tag/release has since appeared (delayed publish).
    - The version is now recognised as dev/pre-release (rule change).
    - The resolver no longer finds a GitHub repo (so we skip it).
    """
    now = datetime.now(timezone.utc)
    recheck_threshold = timedelta(hours=1)

    with state.lock:
        snapshot = list(state.flagged)

    # Filter to entries that are at least 1 hour old
    candidates = []
    for entry in snapshot:
        flagged_at_str = entry.get("flagged_at", "")
        if not flagged_at_str:
            continue
        try:
            flagged_at = datetime.fromisoformat(flagged_at_str)
            if flagged_at.tzinfo is None:
                flagged_at = flagged_at.replace(tzinfo=timezone.utc)
            age = now - flagged_at
            if age >= recheck_threshold:
                candidates.append((entry, age))
        except (ValueError, TypeError):
            continue

    if not candidates:
        return  # nothing old enough to re-check yet

    state.add_log(
        f"Re-verifying {len(candidates)} flagged packages (≥1 hour old) …"
    )

    resolved_keys: list[tuple] = []

    for entry, age in candidates:
        if state._stop_event.is_set():
            break
        name = entry.get("name", "")
        version = entry.get("version", "")
        age_str = f"{int(age.total_seconds() // 3600)}h{int((age.total_seconds() % 3600) // 60)}m"

        # Skip dev/pre-release versions (new rule)
        if _is_dev_version(version):
            resolved_keys.append((name, version))
            state.add_log(f"  ↻ {name} {version} – dev/pre-release, removing flag")
            continue

        owner = entry.get("github_owner")
        repo_name = entry.get("github_repo")
        if not owner or not repo_name:
            continue

        try:
            vr = verify_version(name, version, owner, repo_name)
            if vr.has_release or vr.has_tag:
                resolved_keys.append((name, version))
                state.add_log(
                    f"  ↻ {name} {version} – release appeared after {age_str}, clearing flag"
                )
            else:
                state.add_log(
                    f"  ✗ {name} {version} – still no match after {age_str}"
                )
        except Exception:
            pass  # leave flag as-is if re-check fails

    if resolved_keys:
        resolved_set = set(resolved_keys)
        with state.lock:
            state.flagged = [
                d for d in state.flagged
                if (d.get("name", ""), d.get("version", "")) not in resolved_set
            ]
            state.total_flagged = len(state.flagged)
            # Recount severities
            state.severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for d in state.flagged:
                sev = d.get("severity", "")
                if sev in state.severity_counts:
                    state.severity_counts[sev] += 1

        # Also update the persisted file
        path = config.FLAGGED_OUTPUT_FILE
        if os.path.exists(path):
            try:
                with open(path, "r") as fh:
                    data = json.load(fh)
                data = [
                    d for d in data
                    if (d.get("name", ""), d.get("version", "")) not in resolved_set
                ]
                with open(path, "w") as fh:
                    json.dump(data, fh, indent=2, default=str)
            except Exception:
                pass

        state.add_log(f"Re-verification done – cleared {len(resolved_keys)} stale flags.")
    else:
        state.add_log("Re-verification done – no stale flags found.")


_monitor_thread: threading.Thread | None = None


def _start_monitor():
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        return False
    state._stop_event.clear()
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True, name="monitor")
    _monitor_thread.start()
    return True


def _stop_monitor():
    state._stop_event.set()
    state.add_log("Stop signal sent to monitor thread.")


# ── Flask routes – Pages ────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/flagged")
def flagged_page():
    return render_template("flagged.html")


@app.route("/logs")
def logs_page():
    return render_template("logs.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


# ── Flask routes – API ──────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    return jsonify(state.snapshot())


@app.route("/api/flagged")
def api_flagged():
    severity = request.args.get("severity", "").upper()
    search = request.args.get("search", "").lower()
    with state.lock:
        data = list(state.flagged)

    if severity:
        data = [d for d in data if d.get("severity") == severity]
    if search:
        data = [
            d for d in data
            if search in d.get("name", "").lower()
            or search in d.get("author", "").lower()
            or search in d.get("reason", "").lower()
        ]
    return jsonify(data)


@app.route("/api/recent")
def api_recent():
    with state.lock:
        return jsonify(list(state.recent_scans))


@app.route("/api/logs")
def api_logs():
    with state.lock:
        return jsonify(list(state.log_lines))


@app.route("/api/monitor/start", methods=["POST"])
def api_start():
    ok = _start_monitor()
    return jsonify({"started": ok})


@app.route("/api/monitor/stop", methods=["POST"])
def api_stop():
    _stop_monitor()
    return jsonify({"stopped": True})


@app.route("/api/settings/interval", methods=["POST"])
def api_interval():
    data = request.get_json(silent=True) or {}
    val = data.get("interval")
    if val is None or not isinstance(val, (int, float)) or val < 10:
        return jsonify({"error": "interval must be >= 10 seconds"}), 400
    state.poll_interval = int(val)
    config.POLL_INTERVAL_SECONDS = int(val)
    state.add_log(f"Poll interval changed to {int(val)}s.")
    return jsonify({"interval": int(val)})


@app.route("/api/trusted")
def api_trusted():
    path = config.TRUSTED_PUBLISHERS_FILE
    if not os.path.exists(path):
        return jsonify([])
    with open(path) as fh:
        return jsonify(json.load(fh))


@app.route("/api/trusted", methods=["POST"])
def api_trusted_add():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    note = data.get("note", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400

    path = config.TRUSTED_PUBLISHERS_FILE
    existing = []
    if os.path.exists(path):
        with open(path) as fh:
            existing = json.load(fh)

    if any(e["name"].lower() == name.lower() for e in existing):
        return jsonify({"error": "already exists"}), 409

    existing.append({"name": name, "note": note})
    with open(path, "w") as fh:
        json.dump(existing, fh, indent=2)

    # Clear the cached trusted set so flagger reloads
    import flagger
    flagger._trusted = None

    state.add_log(f"Added trusted publisher: {name}")
    return jsonify({"ok": True})


@app.route("/api/trusted/<name>", methods=["DELETE"])
def api_trusted_delete(name: str):
    path = config.TRUSTED_PUBLISHERS_FILE
    if not os.path.exists(path):
        return jsonify({"error": "not found"}), 404

    with open(path) as fh:
        existing = json.load(fh)

    new_list = [e for e in existing if e["name"].lower() != name.lower()]
    if len(new_list) == len(existing):
        return jsonify({"error": "not found"}), 404

    with open(path, "w") as fh:
        json.dump(new_list, fh, indent=2)

    import flagger
    flagger._trusted = None

    state.add_log(f"Removed trusted publisher: {name}")
    return jsonify({"ok": True})


# ── Logging bridge ──────────────────────────────────────────────────────────

class _WebLogHandler(logging.Handler):
    """Push stdlib log records into the in-memory web log buffer."""

    def emit(self, record):
        try:
            msg = self.format(record)
            state.add_log(msg)
        except Exception:
            pass


def _setup_logging():
    fmt = "%(levelname)-8s  %(name)s  %(message)s"
    handler = _WebLogHandler()
    handler.setFormatter(logging.Formatter(fmt))

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)

    file_handler = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s  " + fmt))
    root.addHandler(file_handler)


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _setup_logging()
    _load_persisted_flags()
    _start_monitor()
    port = int(os.environ.get("PORT", 8050))
    print("\n  ╔══════════════════════════════════════════════════╗")
    print(f"  ║  PyPI ↔ GitHub Monitor – Web Dashboard           ║")
    print(f"  ║  http://127.0.0.1:{port:<38}║")
    print("  ╚══════════════════════════════════════════════════╝\n")
    app.run(host="127.0.0.1", port=port, debug=False)
