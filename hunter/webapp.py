"""
PyPI ↔ GitHub Release Monitor – Web UI (24/7 pipeline).

Run:
    python webapp.py
    # Visit http://127.0.0.1:8050
"""

import logging
import os
import threading
import time
from collections import deque
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template, request, session

from . import config
from . import db as _db
from .flagger import FlaggedPackage, classify, save_flagged, _is_dev_version
from .github_checker import verify_version
from .pipeline import Pipeline, Status
from .pypi_feed import FeedPoller, PackageUpdate

# ── Flask app ───────────────────────────────────────────────────────────────

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__, template_folder=os.path.join(_PROJECT_ROOT, "templates"))
app.secret_key = os.environ.get("SECRET_KEY", "hunter-teampcp-session-key-change-me")


# ── Visitor tracking middleware ─────────────────────────────────────────────

@app.before_request
def _track_visitor():
    """Log every page visit (skip static / API polling noise)."""
    path = request.path
    if path.startswith("/api/"):
        return  # Don't log API polling
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        if "," in ip:
            ip = ip.split(",")[0].strip()
        ua = request.headers.get("User-Agent", "")[:256]
        _db.record_visit(ip, path, ua)
    except Exception:
        pass

# ── In-memory state shared between monitor thread & web routes ──────────────

class MonitorState:
    """Thread-safe shared state for the monitoring pipeline.

    Persistent data (flagged, scans, settings) lives in SQLite.
    Only ephemeral runtime state (queue snapshot, log buffer) is in-memory.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.started_at: str | None = None
        self.last_poll: str | None = None
        self.next_poll: str | None = None
        self.poll_interval = config.POLL_INTERVAL_SECONDS
        self._stop_event = threading.Event()
        # Queue status from pipeline (ephemeral)
        self.queue_snapshot_data: dict = {}
        # In-memory log buffer (also persisted to DB)
        self.log_lines: deque = deque(maxlen=500)

    def add_log(self, msg: str):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{ts}]  {msg}"
        with self.lock:
            self.log_lines.appendleft(formatted)
        try:
            _db.add_log(msg)
        except Exception:
            pass

    def add_flagged(self, flag: FlaggedPackage):
        d = asdict(flag)
        _db.upsert_flagged(d)

    def add_scan(self, name: str, version: str, flagged: bool, **kwargs):
        _db.add_scan(name, version, flagged, **kwargs)

    def snapshot(self) -> dict:
        with self.lock:
            qs = self.queue_snapshot_data
        sev = _db.get_severity_counts()
        total_flagged = _db.get_flagged_count()
        total_scanned = _db.get_total_scanned()
        return {
            "running": self.running,
            "started_at": self.started_at or _db.get_setting("started_at"),
            "last_poll": self.last_poll or _db.get_setting("last_poll"),
            "next_poll": self.next_poll,
            "total_scanned": total_scanned,
            "total_flagged": total_flagged,
            "severity_counts": sev,
            "poll_interval": self.poll_interval,
            "num_workers": config.NUM_WORKERS,
            "queue": {
                "queued": len(qs.get("queued", [])),
                "active": len(qs.get("active", [])),
                "batch_total": qs.get("batch_total", 0),
                "batch_done": qs.get("batch_done", 0),
                "batch_progress": qs.get("batch_progress", 0),
                "processing_rate": qs.get("processing_rate", 0),
            },
            "cache_stats": qs.get("cache_stats", {}),
        }


state = MonitorState()

# ── Background monitor thread (Pipeline-based) ────────────────────────────

# Create the global pipeline instance
pipeline = Pipeline(
    num_workers=config.NUM_WORKERS,
    on_flagged=lambda f: (state.add_flagged(f), save_flagged([f])),
    on_scan=lambda n, v, f, **kw: state.add_scan(n, v, f, **kw),
    on_log=lambda m: state.add_log(m),
    on_status=lambda w: _update_queue_snapshot(),
)


def _update_queue_snapshot():
    """Refresh the queue snapshot in shared state."""
    with state.lock:
        state.queue_snapshot_data = pipeline.queue_snapshot()


def _monitor_loop():
    """Continuous polling loop using concurrent pipeline.

    Wrapped in a top-level try/except so the thread never dies silently.
    If a poll cycle crashes, the thread logs the error and retries after
    a short delay.
    """
    poller = FeedPoller()
    state.add_log(f"Monitor started ({config.NUM_WORKERS} workers).")
    state.started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        _db.set_setting("started_at", state.started_at)
    except Exception as exc:
        state.add_log(f"[WARN] DB write failed (started_at): {exc}")
    poll_count = 0

    while not state._stop_event.is_set():
        try:
            poll_count += 1
            with state.lock:
                state.running = True
                state.last_poll = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            try:
                _db.set_setting("last_poll", state.last_poll)
            except Exception:
                pass

            # Sync already-flagged keys from DB
            already = _db.get_flagged_keys()
            pipeline.set_already_flagged(already)

            state.add_log("Polling PyPI RSS feed …")
            updates = poller.poll_once()

            if updates:
                state.add_log(f"Found {len(updates)} new updates.")
                pipeline.enqueue(updates)
                _update_queue_snapshot()
                pipeline.process_queue()
                _update_queue_snapshot()
            else:
                state.add_log("No new updates in feed.")

            # Re-verify flagged packages >= 30 min old
            if poll_count % config.REVERIFY_EVERY_N_POLLS == 0:
                _reverify_stale_flags()

        except Exception as exc:
            state.add_log(f"[ERROR] Monitor loop error: {exc}")
            logger.exception("Monitor loop error")
            # Brief pause before retrying
            for _ in range(10):
                if state._stop_event.is_set():
                    break
                time.sleep(1)
            continue

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
    candidates = _db.get_flagged_for_reverify(min_age_seconds=config.REVERIFY_MIN_AGE_SECONDS)

    if not candidates:
        return

    now = datetime.now(timezone.utc)
    state.add_log(
        f"Re-verifying {len(candidates)} flagged packages (≥1 hour old) …"
    )

    resolved_keys: list[tuple] = []

    for entry in candidates:
        if state._stop_event.is_set():
            break
        name = entry.get("name", "")
        version = entry.get("version", "")
        flagged_at_str = entry.get("flagged_at", "")
        try:
            flagged_at = datetime.fromisoformat(flagged_at_str)
            if flagged_at.tzinfo is None:
                flagged_at = flagged_at.replace(tzinfo=timezone.utc)
            age = now - flagged_at
        except (ValueError, TypeError):
            age = timedelta(hours=2)  # assume old

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
            # Invalidate caches so we get fresh GitHub data
            from .pipeline import invalidate_caches_for
            invalidate_caches_for(name, owner, repo_name)

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
            logger.warning("Re-verify failed for %s %s", name, version, exc_info=True)
            state.add_log(f"  ⚠ {name} {version} – re-verify error, keeping flag")

    if resolved_keys:
        removed = _db.delete_flagged_batch(resolved_keys)
        state.add_log(f"Re-verification done – cleared {removed} stale flags.")
    else:
        state.add_log("Re-verification done – no stale flags resolved.")


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


@app.route("/queue")
def queue_page():
    return render_template("queue.html")


# ── Admin helpers ───────────────────────────────────────────────────────────

def _load_admin_password() -> str:
    """Load admin password from env var or .secrets file."""
    pw = os.environ.get("ADMIN_RESET_PASSWORD", "").strip()
    if not pw:
        secrets_path = os.path.join(_PROJECT_ROOT, ".secrets")
        if os.path.isfile(secrets_path):
            with open(secrets_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ADMIN_RESET_PASSWORD="):
                        pw = line.split("=", 1)[1].strip()
                        break
    return pw


@app.route("/admin")
def admin_page():
    if not session.get("admin_authed"):
        return render_template("admin_login.html")
    return render_template("admin.html")


# ── Login rate limiting ────────────────────────────────────────────────────
_login_attempts: dict = {}  # ip -> (count, first_attempt_ts)
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 300  # 5 minutes


@app.route("/api/admin/login", methods=["POST"])
def api_admin_login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if "," in ip:
        ip = ip.split(",")[0].strip()

    now = time.time()
    count, first_ts = _login_attempts.get(ip, (0, now))
    if now - first_ts > _LOGIN_WINDOW_SECONDS:
        count, first_ts = 0, now
    if count >= _LOGIN_MAX_ATTEMPTS:
        return jsonify({"error": f"Too many attempts. Try again in {int(_LOGIN_WINDOW_SECONDS - (now - first_ts))}s"}), 429

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    admin_pw = _load_admin_password()
    if not admin_pw:
        return jsonify({"error": "No admin password configured (set ADMIN_RESET_PASSWORD env var)"}), 403
    if password != admin_pw:
        _login_attempts[ip] = (count + 1, first_ts)
        return jsonify({"error": "Invalid password"}), 403
    _login_attempts.pop(ip, None)
    session["admin_authed"] = True
    return jsonify({"ok": True})


@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    session.pop("admin_authed", None)
    return jsonify({"ok": True})


@app.route("/api/admin/visitors")
def api_admin_visitors():
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({
        "stats": _db.get_visitor_stats(),
        "online": _db.get_online_visitors(minutes=5),
        "recent": _db.get_visitors(limit=200),
    })


# ── Flask routes – API ──────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    return jsonify(state.snapshot())


@app.route("/api/flagged")
def api_flagged():
    severity = request.args.get("severity", "").upper()
    search = request.args.get("search", "").lower()
    data = _db.get_all_flagged(severity=severity, search=search)
    return jsonify(data)


@app.route("/api/recent")
def api_recent():
    return jsonify(_db.get_recent_scans(limit=200))


@app.route("/api/queue")
def api_queue():
    return jsonify(pipeline.queue_snapshot())


@app.route("/api/logs")
def api_logs():
    # Combine in-memory buffer (most recent) with DB
    with state.lock:
        mem_logs = list(state.log_lines)
    if len(mem_logs) >= 500:
        return jsonify(mem_logs)
    # Fill from DB if in-memory buffer is short (e.g. after restart)
    db_logs = _db.get_logs(limit=500)
    # Merge: mem_logs are newest, db_logs fill the gap
    seen = set(mem_logs)
    for log in db_logs:
        if log not in seen:
            mem_logs.append(log)
        if len(mem_logs) >= 500:
            break
    return jsonify(mem_logs)


@app.route("/api/monitor/start", methods=["POST"])
def api_start():
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403
    ok = _start_monitor()
    return jsonify({"started": ok})


@app.route("/api/monitor/stop", methods=["POST"])
def api_stop():
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403
    _stop_monitor()
    return jsonify({"stopped": True})


@app.route("/api/settings/interval", methods=["POST"])
def api_interval():
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    val = data.get("interval")
    if val is None or not isinstance(val, (int, float)) or val < 10:
        return jsonify({"error": "interval must be >= 10 seconds"}), 400
    state.poll_interval = int(val)
    config.POLL_INTERVAL_SECONDS = int(val)
    _db.set_setting("poll_interval", str(int(val)))
    state.add_log(f"Poll interval changed to {int(val)}s.")
    return jsonify({"interval": int(val)})


@app.route("/api/settings/workers", methods=["POST"])
def api_workers():
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    val = data.get("workers")
    if val is None or not isinstance(val, int) or val < 1 or val > 16:
        return jsonify({"error": "workers must be 1-16"}), 400
    config.NUM_WORKERS = val
    pipeline._num_workers = val
    _db.set_setting("num_workers", str(val))
    state.add_log(f"Worker count changed to {val}.")
    return jsonify({"workers": val})


@app.route("/api/trusted")
def api_trusted():
    return jsonify(_db.get_trusted_publishers())


@app.route("/api/trusted", methods=["POST"])
def api_trusted_add():
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    note = data.get("note", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400

    if not _db.add_trusted_publisher(name, note):
        return jsonify({"error": "already exists"}), 409

    state.add_log(f"Added trusted publisher: {name}")
    return jsonify({"ok": True})


@app.route("/api/trusted/<name>", methods=["DELETE"])
def api_trusted_delete(name: str):
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403
    if not _db.remove_trusted_publisher(name):
        return jsonify({"error": "not found"}), 404

    state.add_log(f"Removed trusted publisher: {name}")
    return jsonify({"ok": True})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Hard-reset the database: clear all scans, flags, feed state, and logs."""
    if not session.get("admin_authed"):
        return jsonify({"error": "Unauthorized"}), 403

    # Stop the monitor first if running
    was_running = state.running
    if was_running:
        _stop_monitor()
        time.sleep(1)

    _db.hard_reset()

    # Clear in-memory state
    with state.lock:
        state.log_lines.clear()
        state.queue_snapshot_data = {}
    pipeline.set_already_flagged(set())

    state.add_log("🔴 Hard reset performed — all data cleared.")
    return jsonify({"ok": True, "was_running": was_running})


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


# ── App factory (for gunicorn / Fly.io) ─────────────────────────────────────

_initialized = False


def create_app():
    """Initialise DB, restore settings, and start monitor once."""
    global _initialized
    if _initialized:
        return app
    _initialized = True

    _setup_logging()

    # Warn about default SECRET_KEY
    if app.secret_key == "hunter-teampcp-session-key-change-me":
        logger.warning(
            "Using default SECRET_KEY – set SECRET_KEY env var for production!"
        )

    _db.init_db()
    _db.migrate_from_json()

    saved_interval = _db.get_setting_int("poll_interval", config.POLL_INTERVAL_SECONDS)
    state.poll_interval = saved_interval
    config.POLL_INTERVAL_SECONDS = saved_interval
    saved_workers = _db.get_setting_int("num_workers", config.NUM_WORKERS)
    config.NUM_WORKERS = saved_workers
    pipeline._num_workers = saved_workers

    _start_monitor()
    return app


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 8050))
    print("\n  ╔══════════════════════════════════════════════════╗")
    print(f"  ║  PyPI ↔ GitHub Monitor – Web Dashboard           ║")
    print(f"  ║  http://127.0.0.1:{port:<38}║")
    print(f"  ║  Database: {_db.DB_PATH:<43}║")
    print("  ╚══════════════════════════════════════════════════╝\n")
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False)
