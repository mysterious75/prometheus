"""Central SSL verify flag — toggleable via --no-verify or PROMETHEUS_SSL_VERIFY env var.

Usage:
    prometheus scan target.com           # verify=True (default)
    prometheus --no-verify scan target.com  # verify=False
    PROMETHEUS_SSL_VERIFY=0 prometheus scan target.com  # via env var
"""

import os

_verify_ssl = os.environ.get("PROMETHEUS_SSL_VERIFY", "1") not in ("0", "false", "no", "")


def set_verify(value: bool) -> None:
    global _verify_ssl
    _verify_ssl = value


def ssl_verify() -> bool:
    return _verify_ssl
