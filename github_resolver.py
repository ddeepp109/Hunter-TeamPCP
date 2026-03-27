"""
Resolve the GitHub repository (owner/repo) for a given PyPI package.

Strategy (in order):
  1. Inspect the PyPI JSON metadata for project_urls / home_page containing
     a GitHub URL.
  2. Fall back to the package description body for any GitHub URL.

No packages are downloaded – only JSON metadata is fetched.
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests

import config

logger = logging.getLogger(__name__)

_GH_REPO_RE = re.compile(
    r"github\.com/(?P<owner>[A-Za-z0-9\-_.]+)/(?P<repo>[A-Za-z0-9\-_.]+)"
)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "pypi-github-monitor/1.0 (security research)",
    "Accept": "application/json",
})


@dataclass
class PyPIMetadata:
    """Subset of PyPI JSON API data we care about."""
    name: str
    version: str
    summary: str
    author: str
    home_page: str
    project_urls: Dict[str, str]
    description: str            # long description body
    maintainer: str
    maintainer_email: str
    author_email: str
    package_url: str


def fetch_pypi_metadata(package: str) -> Optional[PyPIMetadata]:
    """Fetch metadata from the PyPI JSON API (no download)."""
    url = config.PYPI_JSON_API.format(package=package)
    try:
        time.sleep(config.REQUEST_DELAY_SECONDS)
        resp = _SESSION.get(url, timeout=30)
        if resp.status_code == 404:
            logger.warning("Package not found on PyPI: %s", package)
            return None
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("PyPI API error for %s: %s", package, exc)
        return None

    info = resp.json().get("info", {})
    return PyPIMetadata(
        name=info.get("name", package),
        version=info.get("version", ""),
        summary=info.get("summary", ""),
        author=info.get("author", "") or "",
        home_page=info.get("home_page", "") or "",
        project_urls=info.get("project_urls") or {},
        description=info.get("description", "") or "",
        maintainer=info.get("maintainer", "") or "",
        maintainer_email=info.get("maintainer_email", "") or "",
        author_email=info.get("author_email", "") or "",
        package_url=info.get("package_url", "") or "",
    )


def _extract_gh_owner_repo(text: str) -> Optional[Tuple[str, str]]:
    """Return (owner, repo) from a string containing a GitHub URL."""
    match = _GH_REPO_RE.search(text)
    if not match:
        return None
    owner = match.group("owner")
    repo = match.group("repo")
    # Strip common suffixes (.git, trailing slashes handled by regex)
    repo = re.sub(r"\.git$", "", repo)
    return (owner, repo)


def find_github_repo(meta: PyPIMetadata) -> Optional[Tuple[str, str]]:
    """Try to find the GitHub owner/repo for the package.

    Returns (owner, repo) or None.
    """
    # 1. Check project_urls (most reliable)
    url_priority = [
        "Source",
        "Source Code",
        "Repository",
        "GitHub",
        "Homepage",
        "Home",
        "Code",
        "Bug Tracker",
        "Issues",
    ]
    for key in url_priority:
        if key in meta.project_urls:
            result = _extract_gh_owner_repo(meta.project_urls[key])
            if result:
                return result

    # Scan all project_urls values we haven't tried yet
    for key, val in meta.project_urls.items():
        result = _extract_gh_owner_repo(val)
        if result:
            return result

    # 2. Check home_page
    if meta.home_page:
        result = _extract_gh_owner_repo(meta.home_page)
        if result:
            return result

    # 3. Intentionally do NOT scan the README description body.
    #    Description-scraped GitHub URLs are unreliable — they often reference
    #    unrelated projects mentioned in docs (e.g. nova-act → aws/nova-act-extension,
    #    komorebi-mpl → rngKomorebi/LinoSPAD2).  Only explicit project_urls and
    #    home_page are trustworthy for repo resolution.

    return None
