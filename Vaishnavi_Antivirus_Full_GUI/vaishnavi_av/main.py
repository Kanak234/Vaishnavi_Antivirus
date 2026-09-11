"""CLI entrypoint for the modular antivirus package."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from .logger import setup_logger
from .scanner import scan_path

__version__ = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="vaishnavi-av",
        description="Vaishnavi Antivirus - Cybersecurity Suite with signature detection, heuristics, and quarantine.",
    )
    parser.add_argument("target", nargs="?", default=".", help="File or folder to scan (default: current directory)")
    parser.add_argument(
        "--max-files",
        type=int,
        default=1000,
        help="Maximum number of files to inspect (default: 1000)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    """Main execution function for CLI invocation."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logger = setup_logger()
    logger.info("Starting scan of %s", args.target)
    findings = scan_path(args.target, logger=logger, max_files=args.max_files)
    logger.info("Scan complete. %d findings.", len(findings))
    for f in findings:
        logger.info("Found: %s (%s)", f["path"], f["reason"])
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(run())
