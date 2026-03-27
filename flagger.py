"""
Flagging engine – decides whether a package update is suspicious and
persists flagged results for analyst review.

Severity levels:
  CRITICAL – Has a GitHub repo, but the published version has NO release AND
             no tag.  Strongest indicator of a compromised or hijacked package.
  HIGH     – Package lists a GitHub repo that doesn't exist or is private.
  LOW      – Grace-period exemption (version published very recently – may
             appear on GitHub soon).
  INFO     – Package is on the trusted publishers list.

Packages with NO linked GitHub repository are silently skipped (not flagged).
"""

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set

from packaging.version import Version, InvalidVersion

import config
from github_checker import VerificationResult
from github_resolver import PyPIMetadata


# ── Dev / pre-release filter ─────────────────────────────────────────────────

_DEV_VERSION_RE = re.compile(
    r"(\.|^)(dev|alpha|a\d|b\d|rc\d|SNAPSHOT|post)",
    re.IGNORECASE,
)


def _is_dev_version(version: str) -> bool:
    """Return True for dev/alpha/beta/RC/SNAPSHOT versions that are
    commonly published to PyPI without a corresponding GitHub tag."""
    try:
        v = Version(version)
        return v.is_devrelease or v.is_prerelease
    except InvalidVersion:
        pass
    return bool(_DEV_VERSION_RE.search(version))

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class FlaggedPackage:
    """A package that has been flagged for suspicious publishing behaviour."""
    name: str
    version: str
    severity: str
    reason: str
    pypi_link: str
    github_owner: Optional[str] = None
    github_repo: Optional[str] = None
    author: str = ""
    author_email: str = ""
    summary: str = ""
    flagged_at: str = ""
    verification: Optional[Dict] = None
    pypi_version: str = ""              # version published on PyPI
    github_releases: Optional[List[str]] = None   # latest releases on GitHub
    github_tags: Optional[List[str]] = None       # latest tags on GitHub
    # Risk signals from pypi_analyzer
    risk_signals: Optional[List[str]] = None      # e.g. ["RAPID_PUBLISH(16min)"]
    confidence_score: int = 0                     # 0-100, higher = more suspicious
    monthly_downloads: Optional[int] = None
    rapid_publish_gap: Optional[float] = None     # minutes between this and prior version
    yanked_versions: Optional[List[str]] = None


# ── Version comparison helpers ───────────────────────────────────────────────

_TAG_VERSION_RE = re.compile(
    r"v?(?P<ver>\d+(?:\.\d+)*(?:(?:a|alpha|b|beta|rc|c|dev|pre|post)[\.-]?\d*)*)$"
)


def _extract_version(tag: str) -> Optional[Version]:
    """Try to extract a PEP 440 Version from a git tag name."""
    # Strip common prefixes like "release-", "package-name/", etc.
    name = tag.rsplit("/", 1)[-1]          # package/v1.2.3 → v1.2.3
    name = re.sub(r"^release-", "", name)  # release-1.2.3 → 1.2.3
    # Normalise semver pre-release separators → PEP 440 BEFORE regex
    # e.g. 5.0.0-rc16 → 5.0.0rc16, 5.0.0-rc.16 → 5.0.0rc16
    name = re.sub(
        r"[.\-](rc|alpha|beta|a|b|dev|pre|post)[.\-]?(\d+)",
        r"\1\2",
        name,
        flags=re.IGNORECASE,
    )
    m = _TAG_VERSION_RE.search(name)
    if not m:
        return None
    raw = m.group("ver")
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _github_has_newer(pypi_version: str, gh_releases: List[str], gh_tags: List[str]) -> bool:
    """Return True if GitHub already has a version >= the PyPI version.

    When True the PyPI publish is an older release and not suspicious.
    """
    try:
        pypi_ver = Version(pypi_version)
    except InvalidVersion:
        return False  # can't compare, be safe and don't skip

    for tag in gh_releases + gh_tags:
        gh_ver = _extract_version(tag)
        if gh_ver is not None and gh_ver >= pypi_ver:
            return True
    return False


# Regex to find where a version number starts in a tag name
_VER_START_RE = re.compile(r"v?\d+(?:\.\d+)")


def _is_different_version_series(
    pypi_version: str,
    gh_releases: List[str],
    package_name: str,
) -> bool:
    """Return True when GitHub releases clearly belong to a different version
    series than the PyPI package.

    This catches monorepo false positives like DataDog/integrations-core where
    releases are ``ddev-v14.3.2`` but the PyPI package ``datadog-checks-base``
    publishes ``37.33.1`` — a completely unrelated version series.

    Requires BOTH conditions:
      1. ≥80% of releases are prefixed with a name unrelated to the PyPI package.
      2. The PyPI major version does not appear among any GitHub major versions.
    """
    if not gh_releases:
        return False
    try:
        pypi_ver = Version(pypi_version)
    except InvalidVersion:
        return False

    pkg_norm = re.sub(r"[-_.]", "", package_name.lower())

    gh_versions: List[Version] = []
    unrelated_prefix_count = 0

    for tag in gh_releases:
        stripped = tag.rsplit("/", 1)[-1]
        ver_match = _VER_START_RE.search(stripped)
        if not ver_match:
            continue

        # Everything before the version number is the "prefix"
        prefix = stripped[: ver_match.start()].rstrip("-._/ ")
        prefix_norm = re.sub(r"[-_.]", "", prefix.lower())

        # Prefix is "unrelated" if it's non-empty AND doesn't overlap with
        # the PyPI package name in either direction.
        if prefix_norm and prefix_norm != pkg_norm and not (
            pkg_norm.startswith(prefix_norm) or prefix_norm.startswith(pkg_norm)
        ):
            unrelated_prefix_count += 1

        ver = _extract_version(tag)
        if ver is not None:
            gh_versions.append(ver)

    if not gh_versions:
        return False

    total = len(gh_versions)
    if unrelated_prefix_count < total * 0.8:
        return False  # not enough evidence of unrelated prefixes

    # Check major version overlap
    pypi_major = pypi_ver.major
    gh_majors = {v.major for v in gh_versions}
    if pypi_major not in gh_majors:
        logger.info(
            "%s %s – GitHub releases use different version series "
            "(PyPI major=%d, GH majors=%s), skipping",
            package_name, pypi_version, pypi_major, gh_majors,
        )
        return True

    return False


# ── Trusted publishers ──────────────────────────────────────────────────────

def is_trusted(package_name: str) -> bool:
    import db as _db
    return _db.is_trusted_publisher(package_name)


# ── Classification ──────────────────────────────────────────────────────────

def classify(
    package_name: str,
    version: str,
    pypi_link: str,
    meta: Optional[PyPIMetadata],
    github_repo_found: bool,
    verification: Optional[VerificationResult],
    pub_date: Optional[datetime] = None,
    risk_signals: Optional["RiskSignals"] = None,
) -> Optional[FlaggedPackage]:
    """Evaluate a package update and return a FlaggedPackage or None (clean).

    *risk_signals* is an optional ``pypi_analyzer.RiskSignals`` instance
    carrying additional detection signals (velocity, downloads, yanked, etc.).
    """

    now = datetime.now(timezone.utc)
    flagged_at = now.isoformat()

    # Trusted – log at INFO but don't really flag
    if is_trusted(package_name):
        logger.info("[INFO] %s %s – trusted publisher, skipping", package_name, version)
        return None

    # Grace period – if published < GRACE_PERIOD_HOURS ago we note it as LOW
    in_grace = False
    if pub_date and (now - pub_date) < timedelta(hours=config.GRACE_PERIOD_HOURS):
        in_grace = True

    # Case 0b: Dev/pre-release versions (alpha, beta, rc, dev, SNAPSHOT)
    # These are frequently published to PyPI without a corresponding GitHub tag.
    if _is_dev_version(version):
        logger.debug("%s %s – dev/pre-release version, skipping", package_name, version)
        return None

    # Case 1: No GitHub repo found at all – skip, not suspicious
    if not github_repo_found:
        logger.debug("%s %s – no GitHub repo linked, skipping", package_name, version)
        return None

    if verification is None:
        return None  # shouldn't happen

    # Prepare risk signal fields for the FlaggedPackage
    active_signals = risk_signals.active_signals() if risk_signals else []
    confidence = risk_signals.confidence_score if risk_signals else 0

    def _make_risk_fields() -> dict:
        """Common risk-signal fields for FlaggedPackage construction."""
        if not risk_signals:
            return {}
        return dict(
            risk_signals=active_signals or None,
            confidence_score=confidence,
            monthly_downloads=risk_signals.monthly_downloads,
            rapid_publish_gap=risk_signals.publish_gap_minutes,
            yanked_versions=risk_signals.yanked_versions or None,
        )

    def _severity_from_confidence(base: Severity) -> str:
        """Derive final severity from base + confidence score.

        Confidence score drives prioritisation:
          >= 70  → CRITICAL  (multiple strong signals firing)
          >= 50  → HIGH      (at least one strong signal)
          otherwise keep base severity
        """
        if confidence >= 70:
            return Severity.CRITICAL.value
        if confidence >= 50:
            return Severity.HIGH.value
        return base.value

    # Case 2a: API errors made the check inconclusive – don't flag as
    # CRITICAL / HIGH because we simply couldn't reach GitHub.
    if getattr(verification, "api_error", False):
        # If we still found a tag/release despite some errors, it's clean.
        if verification.has_release or verification.has_tag:
            return None
        return FlaggedPackage(
            name=package_name,
            version=version,
            severity=Severity.LOW.value,
            reason=(
                f"GitHub verification inconclusive (API error/rate-limit) for "
                f"{verification.owner}/{verification.repo}.  Will retry next scan."
            ),
            pypi_link=pypi_link,
            github_owner=verification.owner,
            github_repo=verification.repo,
            author=meta.author if meta else "",
            author_email=meta.author_email if meta else "",
            summary=meta.summary if meta else "",
            flagged_at=flagged_at,
            verification=asdict(verification),
            pypi_version=version,
            github_releases=getattr(verification, "github_releases", [])[:10],
            github_tags=getattr(verification, "github_tags", [])[:10],
            **_make_risk_fields(),
        )

    # Case 2b: GitHub repo referenced but doesn't exist / is private
    # Can't verify releases if repo is gone – skip, don't flag.
    if not verification.repo_exists:
        logger.debug(
            "%s %s – repo %s/%s missing/private, skipping",
            package_name, version, verification.owner, verification.repo,
        )
        return None

    # Case 3: Repo exists but no matching release/tag
    if not verification.has_release and not verification.has_tag:
        gh_rels = getattr(verification, "github_releases", []) or []
        gh_tags = getattr(verification, "github_tags", []) or []

        # If the repo has NO GitHub releases, the maintainer simply
        # doesn't use the Releases feature – not suspicious, skip.
        if not gh_rels:
            logger.info(
                "%s %s – repo %s/%s has no GitHub releases, skipping",
                package_name, version, verification.owner, verification.repo,
            )
            return None

        # If GitHub releases belong to a completely different version series
        # (e.g. monorepo with prefixed releases like ddev-v14.x vs PyPI 37.x),
        # the versions are unrelated — skip.
        if _is_different_version_series(version, gh_rels, package_name):
            return None

        # If GitHub already has a newer (or equal) version, the PyPI
        # publish is just an older release and isn't suspicious.
        if _github_has_newer(version, gh_rels, gh_tags):
            logger.info(
                "%s %s – GitHub already has a newer version, skipping",
                package_name, version,
            )
            return None

        base_sev = Severity.LOW if in_grace else Severity.CRITICAL
        # Build enriched reason with risk signals
        reason_parts = [
            f"PyPI published {version} but GitHub "
            f"({verification.owner}/{verification.repo}) has NO matching "
            f"release or tag and no newer version.",
        ]
        if active_signals:
            reason_parts.append(f"Risk signals: {', '.join(active_signals)}.")
        return FlaggedPackage(
            name=package_name,
            version=version,
            severity=_severity_from_confidence(base_sev),
            reason="  ".join(reason_parts),
            pypi_link=pypi_link,
            github_owner=verification.owner,
            github_repo=verification.repo,
            author=meta.author if meta else "",
            author_email=meta.author_email if meta else "",
            summary=meta.summary if meta else "",
            flagged_at=flagged_at,
            verification=asdict(verification),
            pypi_version=version,
            github_releases=getattr(verification, "github_releases", [])[:10],
            github_tags=getattr(verification, "github_tags", [])[:10],
            **_make_risk_fields(),
        )

    # All good – release/tag found
    return None


# ── Persistence ─────────────────────────────────────────────────────────────

def save_flagged(flags: List[FlaggedPackage]):
    """Persist newly flagged packages to the database.

    De-duplicates by (name, version) — a package+version pair is only
    stored once.  If re-flagged with a higher severity the entry is
    updated in-place.
    """
    import db as _db
    for f in flags:
        _db.upsert_flagged(asdict(f))
    logger.info("Saved %d flagged packages to database", len(flags))


def print_flag_summary(flag: FlaggedPackage):
    """Pretty-print a single flag to the console."""
    sev_colors = {
        "CRITICAL": "\033[91m",  # red
        "HIGH":     "\033[93m",  # yellow
        "MEDIUM":   "\033[33m",  # orange-ish
        "LOW":      "\033[36m",  # cyan
        "INFO":     "\033[37m",  # grey
    }
    reset = "\033[0m"
    color = sev_colors.get(flag.severity, "")
    print(
        f"{color}[{flag.severity}]{reset} "
        f"{flag.name} {flag.version}  "
        f"→  {flag.reason}"
    )
    if flag.github_owner:
        print(f"         GitHub: https://github.com/{flag.github_owner}/{flag.github_repo}")
    print(f"         PyPI:   {flag.pypi_link}")
    print(f"         Author: {flag.author} <{flag.author_email}>")
    print()
