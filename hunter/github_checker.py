"""
Verify whether a specific version exists as a GitHub release or tag.

We check both:
  • /repos/{owner}/{repo}/releases  (formal GitHub releases)
  • /repos/{owner}/{repo}/tags      (lightweight & annotated git tags)

Common tag patterns tried:
  v1.2.3, 1.2.3, release-1.2.3, release/1.2.3, package-1.2.3
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

import requests

from . import config

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "pypi-github-monitor/1.0 (security research)",
    "Accept": "application/vnd.github+json",
})
if config.GITHUB_TOKEN:
    _SESSION.headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"


@dataclass
class VerificationResult:
    """Outcome of checking for a matching GitHub release/tag."""
    package_name: str
    version: str
    owner: str
    repo: str
    has_release: bool           # exact or fuzzy match in /releases
    has_tag: bool               # exact or fuzzy match in /tags
    repo_exists: bool           # whether the GH repo is reachable
    release_names_checked: List[str]
    tag_names_checked: List[str]
    matched_release: Optional[str] = None
    matched_tag: Optional[str] = None
    api_error: bool = False     # True when results are inconclusive due to API errors
    github_releases: List[str] = None      # actual release tag names on GitHub
    github_tags: List[str] = None          # actual tag names on GitHub

    def __post_init__(self):
        if self.github_releases is None:
            self.github_releases = []
        if self.github_tags is None:
            self.github_tags = []


_PEP440_PRE_RE = re.compile(
    r"^(?P<base>.+?)(?P<sep>\.?)(?P<pre>a|alpha|b|beta|rc|c|dev|pre|post)(?P<num>\d+)$",
    re.IGNORECASE,
)


def _normalise_prerelease(version: str) -> List[str]:
    """Return alternate forms of a pre-release version.

    PEP 440 writes ``5.0.0rc16`` while semver uses ``5.0.0-rc16``.
    This generates both so we can match GitHub tags.
    """
    m = _PEP440_PRE_RE.match(version)
    if not m:
        return [version]
    base, _sep, pre, num = m.group("base"), m.group("sep"), m.group("pre"), m.group("num")
    forms = {
        version,                        # 5.0.0rc16  (PEP 440 compact)
        f"{base}-{pre}{num}",           # 5.0.0-rc16 (semver)
        f"{base}.{pre}{num}",           # 5.0.0.rc16
        f"{base}-{pre}.{num}",          # 5.0.0-rc.16
        f"{base}.{pre}.{num}",          # 5.0.0.rc.16
    }
    return list(forms)


def _version_tag_candidates(version: str, package: str = "", repo: str = "") -> List[str]:
    """Generate tag patterns people commonly use for a given version.

    For monorepos (package name != repo name), also generates sub-package
    tag patterns like ``package/v1.2.3`` or ``package-v1.2.3``.
    Handles PEP 440 ↔ semver pre-release format differences.
    """
    ver_forms = _normalise_prerelease(version)

    candidates: List[str] = []
    for v in ver_forms:
        candidates.append(f"v{v}")
        candidates.append(v)
    for v in ver_forms:
        candidates.append(f"release-{v}")
        candidates.append(f"release/{v}")

    if package:
        for v in ver_forms:
            candidates.append(f"{package}-{v}")
            candidates.append(f"{package}-v{v}")
            candidates.append(f"{package}/v{v}")
            candidates.append(f"{package}/{v}")
        if "-" in package:
            norm = package.replace("-", "_")
            for v in ver_forms:
                candidates.append(f"{norm}-{v}")
                candidates.append(f"{norm}-v{v}")

    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


class _ApiError(Exception):
    """Raised when a GitHub API call fails due to rate limiting or network."""


class _RateLimited(Exception):
    """Raised specifically when rate-limited and retries are exhausted."""


def _get_rate_limit_remaining() -> Tuple[int, int]:
    """Query /rate_limit and return (remaining, reset_timestamp).

    Returns (-1, 0) if the endpoint is unreachable.
    """
    try:
        resp = _SESSION.get(f"{config.GITHUB_API}/rate_limit", timeout=10)
        if resp.status_code == 200:
            core = resp.json().get("resources", {}).get("core", {})
            return core.get("remaining", -1), core.get("reset", 0)
    except requests.RequestException:
        pass
    return -1, 0


def _wait_for_rate_reset(reset_ts: int, label: str = "") -> None:
    """Sleep until the rate-limit window resets (capped at 120 s)."""
    wait = max(0, reset_ts - int(time.time())) + 2  # +2 s buffer
    wait = min(wait, 120)  # never wait more than 2 min
    if wait > 0:
        logger.info(
            "Rate limit hit%s – waiting %ds for reset…",
            f" ({label})" if label else "", wait,
        )
        time.sleep(wait)


_MAX_RATE_RETRIES = 2


def _gh_api(path: str, raise_on_error: bool = False) -> Optional[requests.Response]:
    """Make a rate-limit-aware GET to the GitHub API.

    On 403, checks /rate_limit to distinguish genuine rate limits from
    private/forbidden repos.  If rate-limited, waits for reset and retries
    up to ``_MAX_RATE_RETRIES`` times.

    When *raise_on_error* is True, raises ``_ApiError`` on non-rate-limit
    failures so callers can distinguish "not found" from "API down".
    """
    url = f"{config.GITHUB_API}{path}"
    for attempt in range(_MAX_RATE_RETRIES + 1):
        time.sleep(config.REQUEST_DELAY_SECONDS)
        try:
            resp = _SESSION.get(url, timeout=30)
        except requests.RequestException as exc:
            logger.error("GitHub API error (%s): %s", path, exc)
            if raise_on_error:
                raise _ApiError(str(exc)) from exc
            return None

        if resp.status_code != 403:
            return resp

        # Got 403 – determine if it's a rate limit or access denied.
        remaining, reset_ts = _get_rate_limit_remaining()

        if remaining == 0:
            # Confirmed rate limit – wait and retry
            logger.warning(
                "GitHub rate limit confirmed via /rate_limit (attempt %d/%d, path=%s)",
                attempt + 1, _MAX_RATE_RETRIES + 1, path,
            )
            if attempt < _MAX_RATE_RETRIES:
                _wait_for_rate_reset(reset_ts, label=path)
                continue
            # Exhausted retries
            if raise_on_error:
                raise _ApiError(f"Rate limited after {_MAX_RATE_RETRIES + 1} attempts (reset {reset_ts})")
            return None

        # remaining > 0 or unknown (-1): this 403 is NOT a rate limit.
        # The repo is private, DMCA'd, or access is otherwise forbidden.
        logger.info(
            "GitHub 403 on %s is NOT rate-limit (remaining=%s) – repo likely private/forbidden",
            path, remaining,
        )
        return resp  # Return the 403 response so callers can handle it

    return None  # unreachable, but keeps type checker happy


def _repo_exists(owner: str, repo: str) -> Optional[bool]:
    """Return True/False, or None if the check was inconclusive (API error).

    A 403 with remaining quota means private/forbidden → returns False.
    A 403 from rate limiting → returns None (inconclusive).
    """
    try:
        resp = _gh_api(f"/repos/{owner}/{repo}", raise_on_error=True)
    except _ApiError:
        return None  # rate limit exhausted – inconclusive
    if resp is None:
        return None
    if resp.status_code == 403:
        return False  # private or forbidden (not rate-limited)
    return resp.status_code == 200


def _check_single_tag(owner: str, repo: str, tag: str) -> bool:
    """Use the Git refs API to check if a specific tag exists (1 req each)."""
    try:
        resp = _gh_api(f"/repos/{owner}/{repo}/git/ref/tags/{tag}", raise_on_error=True)
    except _ApiError:
        raise  # propagate so caller knows result is inconclusive
    if resp is None:
        raise _ApiError("No response")
    if resp.status_code == 403:
        return False  # private/forbidden, already confirmed not rate-limited
    return resp.status_code == 200


def _check_releases(owner: str, repo: str, candidates: List[str]) -> Tuple[Optional[str], List[str]]:
    """Return (matched_tag_or_None, list_of_all_release_tag_names).

    Raises ``_ApiError`` if the check was inconclusive.
    """
    try:
        resp = _gh_api(f"/repos/{owner}/{repo}/releases?per_page=100", raise_on_error=True)
    except _ApiError:
        raise
    if resp is None:
        raise _ApiError("Releases endpoint returned None")
    if resp.status_code == 403:
        return None, []  # private/forbidden, not rate-limited
    if resp.status_code != 200:
        raise _ApiError(f"Releases endpoint returned {resp.status_code}")

    release_tags = []
    release_tags_set = set()
    for rel in resp.json():
        tag = rel.get("tag_name", "")
        if tag and tag not in release_tags_set:
            release_tags.append(tag)
            release_tags_set.add(tag)

    lower_tags = {t.lower() for t in release_tags_set}
    matched = None
    for c in candidates:
        if c.lower() in lower_tags:
            matched = c
            break
    return matched, release_tags


def _check_tags(owner: str, repo: str, candidates: List[str]) -> Tuple[Optional[str], List[str]]:
    """Return (matched_tag_or_None, list_of_all_tag_names).

    Strategy: first try targeted single-tag lookups for the most likely
    candidates (v{ver}, {ver}), then fall back to listing.
    Raises ``_ApiError`` if the check was inconclusive.
    """
    # Fast path: check the most common patterns directly via refs API
    # Try up to 4 candidates (covers PEP 440 and semver forms)
    for tag_candidate in candidates[:4]:
        try:
            if _check_single_tag(owner, repo, tag_candidate):
                # Still fetch the tag list for UI display
                all_tag_names = _list_tags(owner, repo)
                return tag_candidate, all_tag_names
        except _ApiError:
            raise  # API is unreliable, don't continue

    # Slow path: list tags (paginated up to 300)
    all_tag_names = _list_tags(owner, repo)

    lower_tags = {t.lower() for t in all_tag_names}
    matched = None
    for c in candidates:
        if c.lower() in lower_tags:
            matched = c
            break
    return matched, all_tag_names


def _list_tags(owner: str, repo: str) -> List[str]:
    """List all git tags (paginated, up to 300)."""
    all_tag_names: list = []
    seen: set = set()
    page = 1
    while page <= 3:
        try:
            resp = _gh_api(
                f"/repos/{owner}/{repo}/tags?per_page=100&page={page}",
                raise_on_error=True,
            )
        except _ApiError:
            raise
        if resp is None or resp.status_code == 403:
            break  # 403 = private/forbidden (non-rate-limit), stop paging
        if resp.status_code != 200:
            break
        data = resp.json()
        if not data:
            break
        for t in data:
            name = t.get("name", "")
            if name and name not in seen:
                all_tag_names.append(name)
                seen.add(name)
        page += 1
    return all_tag_names


def verify_version(
    package_name: str,
    version: str,
    owner: str,
    repo: str,
) -> VerificationResult:
    """Check whether *version* is present as a release or tag on GitHub.

    Sets ``api_error=True`` when results are inconclusive (rate-limit /
    network failure) so the classifier can avoid false CRITICAL flags.
    """
    candidates = _version_tag_candidates(version, package_name, repo)

    exists = _repo_exists(owner, repo)
    if exists is None:
        # API error – can't tell if repo exists
        logger.warning("GitHub API error checking %s/%s – marking inconclusive", owner, repo)
        return VerificationResult(
            package_name=package_name,
            version=version,
            owner=owner,
            repo=repo,
            has_release=False,
            has_tag=False,
            repo_exists=False,
            release_names_checked=candidates,
            tag_names_checked=candidates,
            api_error=True,
        )
    if not exists:
        logger.warning("GitHub repo %s/%s not found or private", owner, repo)
        return VerificationResult(
            package_name=package_name,
            version=version,
            owner=owner,
            repo=repo,
            has_release=False,
            has_tag=False,
            repo_exists=False,
            release_names_checked=candidates,
            tag_names_checked=candidates,
        )

    api_error = False
    matched_release = None
    matched_tag = None
    github_releases: List[str] = []
    github_tags: List[str] = []

    try:
        matched_release, github_releases = _check_releases(owner, repo, candidates)
    except _ApiError as exc:
        logger.warning("Release check failed for %s/%s: %s", owner, repo, exc)
        api_error = True

    try:
        matched_tag, github_tags = _check_tags(owner, repo, candidates)
    except _ApiError as exc:
        logger.warning("Tag check failed for %s/%s: %s", owner, repo, exc)
        api_error = True

    result = VerificationResult(
        package_name=package_name,
        version=version,
        owner=owner,
        repo=repo,
        has_release=matched_release is not None,
        has_tag=matched_tag is not None,
        repo_exists=True,
        release_names_checked=candidates,
        tag_names_checked=candidates,
        matched_release=matched_release,
        matched_tag=matched_tag,
        api_error=api_error,
        github_releases=github_releases[:20],
        github_tags=github_tags[:20],
    )

    if matched_release or matched_tag:
        logger.info(
            "%s %s → %s/%s ✓ (release=%s, tag=%s)",
            package_name, version, owner, repo,
            matched_release, matched_tag,
        )
    elif api_error:
        logger.warning(
            "%s %s → %s/%s ⚠ INCONCLUSIVE (API errors)",
            package_name, version, owner, repo,
        )
    else:
        logger.warning(
            "%s %s → %s/%s ✗ NO matching release/tag found",
            package_name, version, owner, repo,
        )

    return result
