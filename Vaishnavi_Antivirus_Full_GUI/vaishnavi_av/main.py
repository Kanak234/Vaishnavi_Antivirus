"""CLI entrypoint for the modular antivirus package."""
import argparse
from .logger import setup_logger
from .scanner import scan_path

def run(argv=None):
    parser = argparse.ArgumentParser(prog="vaishnavi-av")
    parser.add_argument("target", nargs="?", default=".", help="File or folder to scan")
    parser.add_argument("--max-files", type=int, default=1000)
    args = parser.parse_args(argv)

    logger = setup_logger()
    logger.info("Starting scan of %s", args.target)
    findings = scan_path(args.target, logger=logger, max_files=args.max_files)
    logger.info("Scan complete. %d findings.", len(findings))
    for f in findings:
        logger.info("Found: %s (%s)", f["path"], f["reason"])

if __name__ == "__main__":
    run()
