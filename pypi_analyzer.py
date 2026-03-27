"""
Advanced PyPI package analysis — risk signals beyond GitHub tag checks.

Signals detected (used as confidence boosters, not standalone flags):
  1. Rapid version publishing (multiple versions within short window)
  2. Download count scoring (high-value target / attractive supply-chain target)
  3. Yanked version detection (attacker's failed first attempt pattern)

A confidence score (0–100) is computed from these signals to prioritize
flagged packages for analyst review.  Higher score = more suspicious.

No packages are downloaded — only PyPI JSON API metadata is used.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from github_resolver import PyPIMetadata

import requests

import config

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "pypi-github-monitor/1.0 (security research)",
    "Accept": "application/json",
})


@dataclass
class RiskSignals:
    """Collection of risk signals for a single package version."""
    package_name: str
    version: str

    # Version velocity
    rapid_publish: bool = False                 # True if published < 30 min after prior version
    publish_gap_minutes: Optional[float] = None # minutes between this and prior version
    prior_version: str = ""

    # Download stats
    monthly_downloads: Optional[int] = None
    is_high_value: bool = False                 # True if > 50K monthly downloads

    # Yanked versions
    has_yanked_recent: bool = False             # True if a recent adjacent version was yanked
    yanked_versions: List[str] = field(default_factory=list)

    # Confidence score (0-100), higher = more suspicious
    confidence_score: int = 0

    def active_signals(self) -> List[str]:
        """Return list of human-readable active risk signals."""
        signals = []
        if self.rapid_publish:
            gap = f"{self.publish_gap_minutes:.0f}min" if self.publish_gap_minutes else ""
            signals.append(f"RAPID_PUBLISH({gap})")
        if self.is_high_value:
            dl = f"{self.monthly_downloads:,}" if self.monthly_downloads else ""
            signals.append(f"HIGH_VALUE_TARGET({dl}/mo)")
        if self.has_yanked_recent:
            signals.append(f"YANKED_ADJACENT({','.join(self.yanked_versions)})")
        return signals

    def compute_confidence(self, tag_mismatch: bool = True) -> int:
        """Compute a confidence score (0-100) indicating how suspicious this is.

        Scoring model:
          Base: 30 points — the package was already flagged (version not on GitHub)
          +25  Rapid version publish (< 30 min gap, TeamPCP fix-and-republish pattern)
          +15  Yanked adjacent version (attacker's broken first attempt)
          +20  High-value target (> 50K downloads/month — attractive supply-chain target)
          +10  Very high-value target (> 500K downloads/month — top-tier target)
        """
        score = 30 if tag_mismatch else 0

        if self.rapid_publish:
            score += 25
            # Extra points for very rapid publishes (< 10 min)
            if self.publish_gap_minutes is not None and self.publish_gap_minutes < 10:
                score += 5

        if self.has_yanked_recent:
            score += 15

        if self.monthly_downloads is not None:
            if self.monthly_downloads > 500_000:
                score += 30  # top-tier target
            elif self.monthly_downloads > 50_000:
                score += 20  # high-value target
            elif self.monthly_downloads > 10_000:
                score += 10  # moderate target

        self.confidence_score = min(score, 100)
        return self.confidence_score


# ── 1. Version Velocity Check ───────────────────────────────────────────────

def check_version_velocity(package: str, version: str) -> Tuple[bool, Optional[float], str]:
    """Detect rapid successive version publishes (TeamPCP pattern: 16min gap).

    Fetches the full version history and checks time between this version
    and the previous one.

    Returns (is_rapid, gap_minutes, prior_version).
    """
    url = config.PYPI_JSON_API.format(package=package)
    try:
        time.sleep(config.REQUEST_DELAY_SECONDS)
        resp = _SESSION.get(url, timeout=30)
        if resp.status_code != 200:
            return False, None, ""
    except requests.RequestException:
        return False, None, ""

    data = resp.json()
    releases = data.get("releases", {})

    # Build list of (version, upload_time) sorted by upload time
    version_times: List[Tuple[str, datetime]] = []
    for ver, files in releases.items():
        if not files:
            continue
        # Use the earliest upload time for that version
        earliest = None
        for f in files:
            upload_str = f.get("upload_time_iso_8601") or f.get("upload_time", "")
            if not upload_str:
                continue
            try:
                ts = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if earliest is None or ts < earliest:
                    earliest = ts
            except (ValueError, TypeError):
                continue
        if earliest:
            version_times.append((ver, earliest))

    version_times.sort(key=lambda x: x[1])

    # Find the target version and its predecessor
    target_idx = None
    for i, (v, _) in enumerate(version_times):
        if v == version:
            target_idx = i
            break

    if target_idx is None or target_idx == 0:
        return False, None, ""

    prior_ver, prior_time = version_times[target_idx - 1]
    curr_time = version_times[target_idx][1]

    gap = (curr_time - prior_time).total_seconds() / 60.0  # minutes

    # Flag if published within 30 minutes of prior version
    is_rapid = gap < 30.0

    return is_rapid, gap, prior_ver


# ── 2. Download Count Check ─────────────────────────────────────────────────

def get_download_stats(package: str) -> Optional[int]:
    """Get approximate monthly download count from PyPI Stats API.

    Uses pypistats.org API: https://pypistats.org/api/packages/{package}/recent

    Returns monthly download count or None.
    """
    url = f"https://pypistats.org/api/packages/{package}/recent"
    try:
        time.sleep(config.REQUEST_DELAY_SECONDS)
        resp = _SESSION.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return data.get("last_month")
        return None
    except requests.RequestException:
        return None


# ── 3. Yanked Version Detection ─────────────────────────────────────────────

def check_yanked_versions(package: str, version: str) -> Tuple[bool, List[str]]:
    """Check if adjacent versions (numerically close) have been yanked.

    The TeamPCP pattern: 4.87.1 was broken → attacker pushed 4.87.2 fix.
    Both get yanked/quarantined. If we see 4.87.2 and 4.87.1 is yanked,
    that's a strong signal.

    Returns (has_yanked_adjacent, list_of_yanked_versions).
    """
    url = config.PYPI_JSON_API.format(package=package)
    try:
        time.sleep(config.REQUEST_DELAY_SECONDS)
        resp = _SESSION.get(url, timeout=30)
        if resp.status_code != 200:
            return False, []
    except requests.RequestException:
        return False, []

    releases = resp.json().get("releases", {})
    yanked = []
    for ver, files in releases.items():
        if any(f.get("yanked", False) for f in files):
            yanked.append(ver)

    if not yanked:
        return False, []

    # Check if any yanked version is "adjacent" to the target
    # We consider versions that share the same major.minor prefix
    from packaging.version import Version, InvalidVersion
    try:
        target = Version(version)
    except InvalidVersion:
        return bool(yanked), yanked

    adjacent_yanked = []
    for y in yanked:
        try:
            yv = Version(y)
            # Same major.minor
            if yv.major == target.major and yv.minor == target.minor:
                adjacent_yanked.append(y)
        except InvalidVersion:
            continue

    return bool(adjacent_yanked), adjacent_yanked


# ── 4. Full Risk Signal Collection ──────────────────────────────────────────

def analyse_risks(package: str, version: str, skip_downloads: bool = False) -> RiskSignals:
    """Run all risk signal checks for a package version.

    This doesn't download the package — only queries metadata APIs.
    Set skip_downloads=True to skip the pypistats call (rate-limited).
    """
    signals = RiskSignals(package_name=package, version=version)

    # 1. Version velocity
    is_rapid, gap_min, prior_ver = check_version_velocity(package, version)
    signals.rapid_publish = is_rapid
    signals.publish_gap_minutes = gap_min
    signals.prior_version = prior_ver

    # 2. Download stats (optional — pypistats.org has its own rate limits)
    if not skip_downloads:
        monthly = get_download_stats(package)
        if monthly is not None:
            signals.monthly_downloads = monthly
            signals.is_high_value = monthly > 50_000

    # 3. Yanked versions
    has_yanked, yanked_list = check_yanked_versions(package, version)
    signals.has_yanked_recent = has_yanked
    signals.yanked_versions = yanked_list

    # Compute confidence score (tag_mismatch=True will be set by caller if needed)
    signals.compute_confidence(tag_mismatch=True)

    return signals


# ── 5. Optimised entry point (reuses pre-fetched PyPI metadata) ─────────────

def _velocity_from_releases(
    releases: Dict, version: str,
) -> Tuple[bool, Optional[float], str]:
    """Same logic as check_version_velocity but using already-fetched release data."""
    version_times: List[Tuple[str, datetime]] = []
    for ver, files in releases.items():
        if not files:
            continue
        earliest = None
        for f in files:
            upload_str = f.get("upload_time_iso_8601") or f.get("upload_time", "")
            if not upload_str:
                continue
            try:
                ts = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if earliest is None or ts < earliest:
                    earliest = ts
            except (ValueError, TypeError):
                continue
        if earliest:
            version_times.append((ver, earliest))

    version_times.sort(key=lambda x: x[1])
    target_idx = None
    for i, (v, _) in enumerate(version_times):
        if v == version:
            target_idx = i
            break
    if target_idx is None or target_idx == 0:
        return False, None, ""
    prior_ver, prior_time = version_times[target_idx - 1]
    curr_time = version_times[target_idx][1]
    gap = (curr_time - prior_time).total_seconds() / 60.0
    return gap < 30.0, gap, prior_ver


def _yanked_from_releases(
    releases: Dict, version: str,
) -> Tuple[bool, List[str]]:
    """Same logic as check_yanked_versions but using already-fetched release data."""
    from packaging.version import Version, InvalidVersion

    yanked = []
    for ver, files in releases.items():
        if any(f.get("yanked", False) for f in files):
            yanked.append(ver)
    if not yanked:
        return False, []
    try:
        target = Version(version)
    except InvalidVersion:
        return bool(yanked), yanked
    adjacent_yanked = []
    for y in yanked:
        try:
            yv = Version(y)
            if yv.major == target.major and yv.minor == target.minor:
                adjacent_yanked.append(y)
        except InvalidVersion:
            continue
    return bool(adjacent_yanked), adjacent_yanked


def analyse_risks_with_metadata(
    package: str,
    version: str,
    meta: "PyPIMetadata | None" = None,
    pypi_json: Optional[Dict] = None,
    skip_downloads: bool = False,
) -> RiskSignals:
    """Optimised risk analysis that reuses pre-fetched data.

    If *pypi_json* is provided (the full PyPI JSON response), velocity
    and yanked checks are done locally without additional API calls.
    Otherwise falls back to fetching.
    """
    signals = RiskSignals(package_name=package, version=version)

    # 1. Version velocity — use cached JSON if available
    if pypi_json and "releases" in pypi_json:
        is_rapid, gap_min, prior = _velocity_from_releases(
            pypi_json["releases"], version,
        )
    else:
        is_rapid, gap_min, prior = check_version_velocity(package, version)

    signals.rapid_publish = is_rapid
    signals.publish_gap_minutes = gap_min
    signals.prior_version = prior

    # 2. Downloads
    if not skip_downloads:
        monthly = get_download_stats(package)
        if monthly is not None:
            signals.monthly_downloads = monthly
            signals.is_high_value = monthly > 50_000

    # 3. Yanked — use cached JSON if available
    if pypi_json and "releases" in pypi_json:
        has_yanked, yanked_list = _yanked_from_releases(
            pypi_json["releases"], version,
        )
    else:
        has_yanked, yanked_list = check_yanked_versions(package, version)

    signals.has_yanked_recent = has_yanked
    signals.yanked_versions = yanked_list

    signals.compute_confidence(tag_mismatch=True)
    return signals
