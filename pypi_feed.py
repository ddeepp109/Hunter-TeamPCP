"""
Fetch and parse the PyPI recent-updates RSS feed.

The feed at https://pypi.org/rss/updates.xml lists the 40 most recent
package publications.  We parse each <item> to extract the package name
and version, deduplicating against packages we already processed.
"""

import logging
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Set

import requests

import config

logger = logging.getLogger(__name__)


@dataclass
class PackageUpdate:
    """A single update event from the PyPI RSS feed."""
    name: str
    version: str
    link: str
    description: str = ""
    pub_date: Optional[datetime] = None


def _parse_rfc822(date_str: str) -> Optional[datetime]:
    """Best-effort parse of the RFC-822 dates PyPI uses."""
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        return None


def fetch_rss(url: str = config.PYPI_RSS_URL) -> List[PackageUpdate]:
    """Fetch and parse the PyPI RSS updates feed.

    Returns a list of PackageUpdate objects, newest first.
    Does NOT download any package files.
    """
    headers = {"User-Agent": "pypi-github-monitor/1.0 (security research)"}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Failed to fetch RSS feed: %s", exc)
        return []

    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError as exc:
        logger.error("Failed to parse RSS XML: %s", exc)
        return []

    updates: List[PackageUpdate] = []
    for item in root.iter("item"):
        title_el = item.find("title")
        link_el = item.find("link")
        desc_el = item.find("description")
        pub_el = item.find("pubDate")

        if title_el is None or title_el.text is None:
            continue

        # Title format: "<package> <version>"
        parts = title_el.text.strip().rsplit(" ", 1)
        if len(parts) != 2:
            logger.debug("Unexpected title format: %s", title_el.text)
            continue

        name, version = parts
        updates.append(PackageUpdate(
            name=name.strip(),
            version=version.strip(),
            link=link_el.text.strip() if link_el is not None and link_el.text else "",
            description=desc_el.text.strip() if desc_el is not None and desc_el.text else "",
            pub_date=_parse_rfc822(pub_el.text.strip()) if pub_el is not None and pub_el.text else None,
        ))

    logger.info("Fetched %d updates from PyPI RSS feed", len(updates))
    return updates


class FeedPoller:
    """Continuously poll the RSS feed, yielding only **new** updates."""

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def _key(self, u: PackageUpdate) -> str:
        return f"{u.name}=={u.version}"

    def poll_once(self) -> List[PackageUpdate]:
        """Return only updates we haven't seen yet."""
        all_updates = fetch_rss()
        new = [u for u in all_updates if self._key(u) not in self._seen]
        for u in new:
            self._seen.add(self._key(u))
        if new:
            logger.info("New updates since last poll: %d", len(new))
        return new

    def run_forever(self, callback):
        """Poll in a loop, calling *callback(updates)* with each batch.

        Blocks forever (Ctrl-C to stop).
        """
        logger.info(
            "Starting continuous poll (interval=%ds)",
            config.POLL_INTERVAL_SECONDS,
        )
        while True:
            new = self.poll_once()
            if new:
                callback(new)
            time.sleep(config.POLL_INTERVAL_SECONDS)
