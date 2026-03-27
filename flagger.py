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


# ── Trusted publishers ──────────────────────────────────────────────────────

_trusted: Optional[Set[str]] = None


def _load_trusted() -> Set[str]:
    global _trusted
    if _trusted is not None:
        return _trusted
    path = config.TRUSTED_PUBLISHERS_FILE
    if not os.path.exists(path):
        _trusted = set()
        return _trusted
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        _trusted = {entry["name"].lower() for entry in data if "name" in entry}
    except Exception as exc:
        logger.error("Failed to load trusted publishers: %s", exc)
        _trusted = set()
    return _trusted


def is_trusted(package_name: str) -> bool:
    return package_name.lower() in _load_trusted()


# ── Classification ──────────────────────────────────────────────────────────

def classify(
    package_name: str,
    version: str,
    pypi_link: str,
    meta: Optional[PyPIMetadata],
    github_repo_found: bool,
    verification: Optional[VerificationResult],
    pub_date: Optional[datetime] = None,
) -> Optional[FlaggedPackage]:
    """Evaluate a package update and return a FlaggedPackage or None (clean)."""

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
        )

    # Case 2b: GitHub repo referenced but doesn't exist / is private
    if not verification.repo_exists:
        severity = Severity.LOW if in_grace else Severity.HIGH
        return FlaggedPackage(
            name=package_name,
            version=version,
            severity=severity.value,
            reason=f"GitHub repo {verification.owner}/{verification.repo} does not exist or is private.",
            pypi_link=pypi_link,
            github_owner=verification.owner,
            github_repo=verification.repo,
            author=meta.author if meta else "",
            author_email=meta.author_email if meta else "",
            summary=meta.summary if meta else "",
            flagged_at=flagged_at,
            verification=asdict(verification),
            pypi_version=version,
            github_releases=[],
            github_tags=[],
        )

    # Case 3: Repo exists but no matching release/tag
    if not verification.has_release and not verification.has_tag:
        gh_rels = getattr(verification, "github_releases", []) or []
        gh_tags = getattr(verification, "github_tags", []) or []

        # If the repo has NO releases AND no tags at all, the maintainer
        # simply doesn't use GitHub releases – not suspicious, skip.
        if not gh_rels and not gh_tags:
            logger.info(
                "%s %s – repo %s/%s has no releases/tags at all, skipping",
                package_name, version, verification.owner, verification.repo,
            )
            return None

        # If GitHub already has a newer (or equal) version, the PyPI
        # publish is just an older release and isn't suspicious.
        if _github_has_newer(version, gh_rels, gh_tags):
            logger.info(
                "%s %s – GitHub already has a newer version, skipping",
                package_name, version,
            )
            return None

        severity = Severity.LOW if in_grace else Severity.CRITICAL
        return FlaggedPackage(
            name=package_name,
            version=version,
            severity=severity.value,
            reason=(
                f"PyPI published {version} but GitHub "
                f"({verification.owner}/{verification.repo}) has NO matching "
                f"release or tag and no newer version.  "
                f"Checked: {', '.join(verification.tag_names_checked[:5])}"
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
        )

    # All good – release/tag found
    return None


# ── Persistence ─────────────────────────────────────────────────────────────

def save_flagged(flags: List[FlaggedPackage], path: str = config.FLAGGED_OUTPUT_FILE):
    """Append newly flagged packages to the JSON output file.

    De-duplicates by (name, version) — a package+version pair is only
    stored once.  If re-flagged with a higher severity the entry is
    updated in-place.
    """
    existing: List[Dict] = []
    if os.path.exists(path):
        try:
            with open(path, "r") as fh:
                existing = json.load(fh)
        except Exception:
            existing = []

    # Build index of existing entries keyed by (name, version)
    idx: Dict[tuple, int] = {}
    for i, e in enumerate(existing):
        key = (e.get("name", ""), e.get("version", ""))
        idx[key] = i

    _SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    for f in flags:
        d = asdict(f)
        key = (f.name, f.version)
        if key in idx:
            # Update only if new severity is higher
            old = existing[idx[key]]
            if _SEV_ORDER.get(f.severity, 0) > _SEV_ORDER.get(old.get("severity", ""), 0):
                existing[idx[key]] = d
        else:
            existing.append(d)
            idx[key] = len(existing) - 1

    with open(path, "w") as fh:
        json.dump(existing, fh, indent=2, default=str)

    logger.info("Saved %d new flags → %s (total: %d)", len(flags), path, len(existing))


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
