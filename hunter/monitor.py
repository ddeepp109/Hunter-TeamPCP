"""
PyPI ↔ GitHub Release Monitor – main entry point.

Usage:
    # Single scan of the current RSS feed
    python monitor.py --once

    # Continuous monitoring (polls every POLL_INTERVAL_SECONDS)
    python monitor.py

    # Override poll interval
    python monitor.py --interval 60

    # Show version
    python monitor.py --version
"""

import argparse
import json
import logging
import sys
from typing import List

from . import config
from .flagger import (
    FlaggedPackage,
    classify,
    print_flag_summary,
    save_flagged,
)
from .github_checker import verify_version
from .github_resolver import fetch_pypi_metadata, find_github_repo
from .pypi_analyzer import analyse_risks
from .pypi_feed import FeedPoller, PackageUpdate

__version__ = "1.0.0"

# ── Logging setup ───────────────────────────────────────────────────────────

def _setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
    ]
    logging.basicConfig(level=level, format=fmt, handlers=handlers)


logger = logging.getLogger(__name__)


# ── Pipeline ────────────────────────────────────────────────────────────────

def analyse_package(update: PackageUpdate) -> FlaggedPackage | None:
    """Run the full analysis pipeline for a single package update.

    1. Fetch PyPI metadata (JSON API, no download).
    2. Resolve GitHub repo from metadata.
    3. Verify release/tag on GitHub.
    4. Classify and optionally flag.
    """
    logger.info("Analysing %s %s …", update.name, update.version)

    meta = fetch_pypi_metadata(update.name)
    if meta is None:
        logger.warning("Could not fetch metadata for %s – skipping", update.name)
        return None

    gh = find_github_repo(meta)
    verification = None

    if gh:
        owner, repo = gh
        logger.info("  GitHub repo: %s/%s", owner, repo)
        verification = verify_version(update.name, update.version, owner, repo)
    else:
        logger.info("  No GitHub repo found in metadata")

    # Run additional risk signal analysis (provenance, velocity, downloads, yanked)
    risk_signals = analyse_risks(update.name, update.version)
    if risk_signals.active_signals():
        logger.info("  Risk signals: %s", ", ".join(risk_signals.active_signals()))

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

    return flag


def process_batch(updates: List[PackageUpdate]):
    """Analyse a batch of updates, flag and persist results."""
    flagged: List[FlaggedPackage] = []

    for update in updates:
        try:
            flag = analyse_package(update)
            if flag:
                flagged.append(flag)
                print_flag_summary(flag)
        except Exception:
            logger.exception("Unexpected error analysing %s %s", update.name, update.version)

    if flagged:
        save_flagged(flagged)
        # Summary
        counts = {}
        for f in flagged:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        logger.info(
            "Batch complete: %d flagged out of %d  (%s)",
            len(flagged),
            len(updates),
            ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())),
        )
    else:
        logger.info("Batch complete: %d packages analysed, none flagged.", len(updates))


# ── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="monitor",
        description="Monitor PyPI releases for missing GitHub source releases.",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan of the RSS feed, then exit.",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=config.POLL_INTERVAL_SECONDS,
        help=f"Polling interval in seconds (default: {config.POLL_INTERVAL_SECONDS}).",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(verbose=args.verbose)
    config.POLL_INTERVAL_SECONDS = args.interval

    logger.info("=" * 60)
    logger.info("PyPI ↔ GitHub Release Monitor v%s", __version__)
    logger.info("=" * 60)

    if config.GITHUB_TOKEN:
        logger.info("GitHub token detected – using authenticated requests.")
    else:
        logger.warning(
            "No GITHUB_TOKEN set. GitHub API rate limit is 60 req/h. "
            "Export GITHUB_TOKEN for 5 000 req/h."
        )

    poller = FeedPoller()

    if args.once:
        updates = poller.poll_once()
        if updates:
            process_batch(updates)
        else:
            logger.info("No new updates in the feed.")
    else:
        logger.info(
            "Starting continuous monitoring (Ctrl-C to stop, interval=%ds)…",
            config.POLL_INTERVAL_SECONDS,
        )
        try:
            poller.run_forever(callback=process_batch)
        except KeyboardInterrupt:
            logger.info("Interrupted – shutting down.")


if __name__ == "__main__":
    main()
