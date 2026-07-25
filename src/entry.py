"""Prometheus v3.0 — AI Security Researcher.

Entry point for the application.
"""

import sys
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    """Main entry point."""
    from src.cli.interface import CLI
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
