"""Auth context — validates scan access via API token.
Direct scanner imports bypass API auth; this provides a second layer.
"""

import os
from typing import Optional

_AUTH_TOKEN: Optional[str] = None


def set_auth_token(token: Optional[str]) -> None:
    global _AUTH_TOKEN
    _AUTH_TOKEN = token


def check_auth() -> bool:
    expected = os.getenv("AUTH_TOKEN", "")
    if not expected:
        return True
    if _AUTH_TOKEN is None:
        return False
    return _AUTH_TOKEN == expected


def require_auth() -> None:
    if not check_auth():
        raise PermissionError("Unauthorized: valid auth token required for scanning")
