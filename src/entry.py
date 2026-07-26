"""Prometheus v3.0 — AI Security Researcher.

Entry point for the application.
"""

import sys
import argparse
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Prometheus Security Testing Platform")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL verification (use for self-signed certs)")
    args, _ = parser.parse_known_args()

    if args.no_verify:
        from src.core.transport import set_verify
        set_verify(False)

    from src.cli.interface import CLI
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
