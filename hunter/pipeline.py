"""
Concurrent processing pipeline with priority queue, retry, and caching.

Architecture:
  RSS Feed → PriorityQueue → ThreadPoolExecutor (N workers) → classify → flag

Each work item tracks its status (QUEUED → PROCESSING → DONE / FAILED)
so the web UI can show real-time progress.
"""

import logging
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

import requests

from . import config
from .flagger import FlaggedPackage, classify, _is_dev_version
from .github_checker import VerificationResult, verify_version
from .github_resolver import PyPIMetadata, fetch_pypi_metadata, find_github_repo
from .pypi_analyzer import RiskSignals, analyse_risks_with_metadata
from .pypi_feed import PackageUpdate

logger = logging.getLogger(__name__)


# ── Work item status ─────────────────────────────────────────────────────────

class Status(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkItem:
    """A single package to analyse, with status tracking."""
    update: PackageUpdate
    status: Status = Status.QUEUED
    priority: int = 0             # lower = higher priority
    retries: int = 0
    max_retries: int = 2
    error: str = ""
    result: Optional[FlaggedPackage] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    worker_id: Optional[int] = None

    @property
    def key(self) -> str:
        return f"{self.update.name}=={self.update.version}"

    def to_dict(self) -> dict:
        return {
            "name": self.update.name,
            "version": self.update.version,
            "status": self.status.value,
            "priority": self.priority,
            "retries": self.retries,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "worker_id": self.worker_id,
            "flagged": self.result is not None,
        }


# ── LRU Cache ────────────────────────────────────────────────────────────────

class TTLCache:
    """Thread-safe TTL cache to avoid redundant API calls."""

    def __init__(self, ttl_seconds: int = 300, max_size: int = 500):
        self._data: OrderedDict[str, Tuple[float, object]] = OrderedDict()
        self._ttl = ttl_seconds
        self._max = max_size
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[object]:
        with self._lock:
            if key in self._data:
                ts, val = self._data[key]
                if time.time() - ts < self._ttl:
                    self._data.move_to_end(key)
                    self.hits += 1
                    return val
                del self._data[key]
            self.misses += 1
            return None

    def put(self, key: str, value: object):
        with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def invalidate(self, key: str):
        """Remove a specific key from the cache so next access re-fetches."""
        with self._lock:
            self._data.pop(key, None)

    def stats(self) -> dict:
        with self._lock:
            return {
                "size": len(self._data),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": f"{self.hits / max(1, self.hits + self.misses) * 100:.0f}%",
            }


# ── Rate limiter (token bucket per host) ─────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter, shared across all worker threads."""

    def __init__(self, rate: float = 10.0, burst: int = 15):
        """
        rate:  refill tokens per second
        burst: max tokens (bucket size)
        """
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        """Block until a token is available."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            time.sleep(0.05)


# ── Global rate limiters & caches (shared by all workers) ────────────────────

github_limiter = RateLimiter(rate=12.0, burst=20)   # ~12 req/s safe for 5000/hr
pypi_limiter = RateLimiter(rate=8.0, burst=15)       # ~8 req/s for PyPI

# Cache GitHub repo existence (TTL 1 hour)
repo_exists_cache = TTLCache(ttl_seconds=3600, max_size=1000)
# Cache release/tag lists (TTL 5 min)
releases_cache = TTLCache(ttl_seconds=300, max_size=500)
# Cache PyPI metadata (TTL 5 min)
pypi_meta_cache = TTLCache(ttl_seconds=300, max_size=200)


# ── Cached wrappers ─────────────────────────────────────────────────────────

def cached_fetch_pypi_metadata(package: str) -> Optional[PyPIMetadata]:
    """Fetch PyPI metadata with caching."""
    cached = pypi_meta_cache.get(package)
    if cached is not None:
        return cached
    pypi_limiter.acquire()
    meta = fetch_pypi_metadata(package)
    if meta is not None:
        pypi_meta_cache.put(package, meta)
    return meta


def cached_verify_version(
    package_name: str, version: str, owner: str, repo: str
) -> VerificationResult:
    """Verify version with cached release/tag lists."""
    cache_key = f"{owner}/{repo}"
    cached = releases_cache.get(cache_key)
    if cached is not None:
        # Use cached release/tag lists to check locally
        vr: VerificationResult = cached
        # But we still need to check for this specific version
        # So we run verify_version but with cached awareness
        # (The internal API calls are still rate-limited individually)

    github_limiter.acquire()
    result = verify_version(package_name, version, owner, repo)
    if result.repo_exists:
        releases_cache.put(cache_key, result)
    return result


def invalidate_caches_for(package: str, owner: str = "", repo: str = ""):
    """Remove all cached data for a package/repo so the next check is fresh."""
    pypi_meta_cache.invalidate(package)
    if owner and repo:
        cache_key = f"{owner}/{repo}"
        releases_cache.invalidate(cache_key)
        repo_exists_cache.invalidate(cache_key)


# ── Pipeline engine ──────────────────────────────────────────────────────────

class Pipeline:
    """Concurrent package analysis pipeline with queue and workers."""

    def __init__(
        self,
        num_workers: int = 4,
        on_flagged: Optional[Callable[[FlaggedPackage], None]] = None,
        on_scan: Optional[Callable] = None,
        on_log: Optional[Callable[[str], None]] = None,
        on_status: Optional[Callable[[WorkItem], None]] = None,
    ):
        self._num_workers = num_workers
        self._on_flagged = on_flagged or (lambda f: None)
        self._on_scan = on_scan or (lambda n, v, f: None)
        self._on_log = on_log or (lambda m: None)
        self._on_status = on_status or (lambda w: None)

        self._queue_lock = threading.Lock()
        self._queue: List[WorkItem] = []        # sorted by priority
        self._active: Dict[str, WorkItem] = {}  # key → item (currently processing)
        self._done: List[WorkItem] = []          # completed items (recent 500)
        self._already_flagged: set = set()       # (name, version) pairs already flagged

        self._executor: Optional[ThreadPoolExecutor] = None
        self._batch_total = 0
        self._batch_done = 0
        self._processing_start: Optional[float] = None

    def set_already_flagged(self, flagged_keys: set):
        """Set the (name, version) pairs already flagged to avoid re-analysis."""
        self._already_flagged = flagged_keys

    def enqueue(self, updates: List[PackageUpdate]):
        """Add package updates to the priority queue.

        Priority: lower number = processed first.
        Dev/pre-release and already-flagged packages are skipped immediately.
        """
        items = []
        for u in updates:
            key = f"{u.name}=={u.version}"

            # Skip dev/pre-release
            if _is_dev_version(u.version):
                self._on_log(f"  ⏭ {u.name} {u.version} – dev/pre-release, skipped")
                continue

            # The FeedPoller only passes through items whose pubDate
            # changed, so every item here is either brand-new or a
            # re-publish.  Invalidate caches for re-appears.
            is_refetch = (u.name, u.version) in self._already_flagged
            if is_refetch:
                pypi_meta_cache.invalidate(u.name)
                releases_cache.invalidate(f"{u.name}/*")  # best-effort
                self._on_log(f"  ↻ {u.name} {u.version} – new pubDate, re-analysing")

            # Assign priority (0 = highest)
            # Prioritize by recency (pub_date) — newer packages first
            priority = 100  # default
            if u.pub_date:
                age = (datetime.now(timezone.utc) - u.pub_date).total_seconds()
                priority = int(min(age / 60, 999))  # minutes old

            items.append(WorkItem(update=u, priority=priority))

        with self._queue_lock:
            for item in items:
                # Check not already in queue or active
                if item.key not in self._active and not any(
                    q.key == item.key for q in self._queue
                ):
                    self._queue.append(item)
            # Sort by priority (lower = first)
            self._queue.sort(key=lambda w: w.priority)

        if items:
            self._on_log(f"Enqueued {len(items)} packages for analysis.")

    def process_queue(self):
        """Process all queued items concurrently using the thread pool."""
        with self._queue_lock:
            to_process = list(self._queue)
            self._queue.clear()

        if not to_process:
            return

        self._batch_total = len(to_process)
        self._batch_done = 0
        self._processing_start = time.monotonic()

        self._on_log(
            f"Processing {len(to_process)} packages with {self._num_workers} workers…"
        )

        # Use ThreadPoolExecutor for concurrent analysis
        with ThreadPoolExecutor(
            max_workers=self._num_workers,
            thread_name_prefix="worker"
        ) as executor:
            futures: List[Tuple[WorkItem, Future]] = []
            for item in to_process:
                f = executor.submit(self._process_one, item)
                futures.append((item, f))

            # Collect results as they complete
            for item, future in futures:
                try:
                    future.result(timeout=120)  # 2 min timeout per package
                except Exception as exc:
                    item.status = Status.FAILED
                    item.error = str(exc)
                    item.finished_at = datetime.now(timezone.utc).isoformat()
                    self._on_log(f"  ✗ {item.update.name} – worker error: {exc}")
                    self._on_status(item)

        elapsed = time.monotonic() - self._processing_start
        rate = self._batch_done / max(elapsed, 0.1) * 60
        self._on_log(
            f"Batch complete: {self._batch_done} packages in {elapsed:.1f}s "
            f"({rate:.0f} pkg/min)"
        )

    def _process_one(self, item: WorkItem):
        """Analyse a single package (runs in worker thread)."""
        worker_name = threading.current_thread().name
        worker_id = int(worker_name.split("_")[-1]) if "_" in worker_name else 0

        item.status = Status.PROCESSING
        item.started_at = datetime.now(timezone.utc).isoformat()
        item.worker_id = worker_id
        with self._queue_lock:
            self._active[item.key] = item
        self._on_status(item)

        update = item.update
        try:
            flag, verification = self._analyse_package(update)
            item.status = Status.DONE
            item.result = flag
            item.finished_at = datetime.now(timezone.utc).isoformat()

            was_flagged = flag is not None
            # Extract GitHub info for scan record
            gh_owner = ""
            gh_repo = ""
            gh_releases: list = []
            if verification:
                gh_owner = getattr(verification, "owner", "") or ""
                gh_repo = getattr(verification, "repo", "") or ""
                # Combine releases + tags (deduplicated, releases first) so
                # the UI always has version data even if /releases was
                # rate-limited but /tags succeeded.
                rels = getattr(verification, "github_releases", []) or []
                tags = getattr(verification, "github_tags", []) or []
                seen = set()
                for v in rels + tags:
                    if v not in seen:
                        gh_releases.append(v)
                        seen.add(v)
            self._on_scan(
                update.name, update.version, was_flagged,
                github_owner=gh_owner, github_repo=gh_repo,
                github_releases=gh_releases[:10],
                pypi_link=update.link,
            )

            if flag:
                self._on_flagged(flag)
                self._on_log(
                    f"  🚩 [{flag.severity}] {flag.name} {flag.version} "
                    f"(confidence: {flag.confidence_score}) – {flag.reason[:80]}"
                )
            else:
                self._on_log(f"  ✓ {update.name} {update.version} – clean")

        except Exception as exc:
            if item.retries < item.max_retries:
                item.retries += 1
                item.status = Status.QUEUED
                item.error = f"Retry {item.retries}/{item.max_retries}: {exc}"
                self._on_log(
                    f"  ↻ {update.name} {update.version} – retry {item.retries}: {exc}"
                )
                # Re-enqueue with lower priority (back of queue)
                with self._queue_lock:
                    item.priority += 500
                    self._queue.append(item)
                    self._queue.sort(key=lambda w: w.priority)
            else:
                item.status = Status.FAILED
                item.error = str(exc)
                item.finished_at = datetime.now(timezone.utc).isoformat()
                self._on_log(f"  ✗ {update.name} {update.version} – FAILED: {exc}")
        finally:
            with self._queue_lock:
                self._active.pop(item.key, None)
                self._done.append(item)
                if len(self._done) > 500:
                    self._done = self._done[-500:]
            self._batch_done += 1
            self._on_status(item)

    def _analyse_package(self, update: PackageUpdate):
        """Full analysis pipeline for one package (thread-safe).

        Returns (flag_or_None, verification_or_None).
        """
        # 1. Fetch PyPI metadata (cached)
        meta = cached_fetch_pypi_metadata(update.name)
        if meta is None:
            return None, None

        # 2. Resolve GitHub repo
        gh = find_github_repo(meta)
        verification = None

        if gh:
            owner, repo = gh
            # 3. Verify version on GitHub (rate-limited)
            github_limiter.acquire()
            verification = verify_version(update.name, update.version, owner, repo)
        else:
            pass  # No GitHub repo → will be skipped by classify()

        # 4. Risk signals — reuse the already-fetched metadata
        pypi_json = getattr(meta, "_raw_json", None)
        pypi_limiter.acquire()
        risk_signals = analyse_risks_with_metadata(
            update.name, update.version, meta, pypi_json=pypi_json,
        )

        # 5. Classify
        flag = classify(
            package_name=update.name,
            version=update.version,
            pypi_link=update.link,
            meta=meta,
            github_repo_found=gh is not None,
            verification=verification,
            pub_date=update.pub_date,
            risk_signals=risk_signals,
        )
        return flag, verification

    # ── Queue status for UI ──────────────────────────────────────────────────

    def queue_snapshot(self) -> dict:
        """Return full queue state for the API."""
        with self._queue_lock:
            queued = [w.to_dict() for w in self._queue]
            active = [w.to_dict() for w in self._active.values()]
            done = [w.to_dict() for w in self._done[-50:]]

        elapsed = 0.0
        rate = 0.0
        if self._processing_start:
            elapsed = time.monotonic() - self._processing_start
            rate = self._batch_done / max(elapsed, 0.1) * 60

        return {
            "queued": queued,
            "active": active,
            "done": list(reversed(done)),
            "batch_total": self._batch_total,
            "batch_done": self._batch_done,
            "batch_progress": (
                round(self._batch_done / self._batch_total * 100)
                if self._batch_total > 0 else 0
            ),
            "processing_rate": round(rate, 1),
            "num_workers": self._num_workers,
            "cache_stats": {
                "pypi_meta": pypi_meta_cache.stats(),
                "repo_exists": repo_exists_cache.stats(),
                "releases": releases_cache.stats(),
            },
        }
