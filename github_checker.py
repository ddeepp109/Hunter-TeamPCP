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

import config

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


def _gh_api(path: str, raise_on_error: bool = False) -> Optional[requests.Response]:
    """Make a rate-limit-aware GET to the GitHub API.

    When *raise_on_error* is True, raises ``_ApiError`` on rate-limit /
    network failures so callers can distinguish "not found" from "API down".
    """
    url = f"{config.GITHUB_API}{path}"
    time.sleep(config.REQUEST_DELAY_SECONDS)
    try:
        resp = _SESSION.get(url, timeout=30)
        if resp.status_code == 403:
            reset = resp.headers.get("X-RateLimit-Reset")
            logger.warning("GitHub rate limit hit (reset: %s)", reset)
            if raise_on_error:
                raise _ApiError(f"Rate limited (reset {reset})")
            return None
        return resp
    except requests.RequestException as exc:
        logger.error("GitHub API error (%s): %s", path, exc)
        if raise_on_error:
            raise _ApiError(str(exc)) from exc
        return None


def _repo_exists(owner: str, repo: str) -> Optional[bool]:
    """Return True/False, or None if the check was inconclusive (API error)."""
    try:
        resp = _gh_api(f"/repos/{owner}/{repo}", raise_on_error=True)
    except _ApiError:
        return None
    if resp is None:
        return None
    return resp.status_code == 200


def _check_single_tag(owner: str, repo: str, tag: str) -> bool:
    """Use the Git refs API to check if a specific tag exists (1 req each)."""
    try:
        resp = _gh_api(f"/repos/{owner}/{repo}/git/ref/tags/{tag}", raise_on_error=True)
    except _ApiError:
        raise  # propagate so caller knows result is inconclusive
    if resp is None:
        raise _ApiError("No response")
    return resp.status_code == 200


def _check_releases(owner: str, repo: str, candidates: List[str]) -> Tuple[Optional[str], List[str]]:
    """Return (matched_tag_or_None, list_of_all_release_tag_names).

    Raises ``_ApiError`` if the check was inconclusive.
    """
    try:
        resp = _gh_api(f"/repos/{owner}/{repo}/releases?per_page=100", raise_on_error=True)
    except _ApiError:
        raise
    if resp is None or resp.status_code != 200:
        raise _ApiError(f"Releases endpoint returned {resp.status_code if resp else 'None'}")

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
        if resp is None or resp.status_code != 200:
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
