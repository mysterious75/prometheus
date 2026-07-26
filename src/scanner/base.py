"""Base scanner — all scanners inherit from this for auth enforcement."""

from ..core.auth_context import require_auth


class BaseScanner:
    """All scanners extend this. Enforces auth on instantiation."""

    def __init__(self):
        require_auth()
