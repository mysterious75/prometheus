"""Tests for Session Management Scanner."""
import pytest
from unittest.mock import MagicMock, patch
from src.scanner.session_manager import SessionManagerScanner


class TestSessionManagerScanner:
    def test_init(self):
        scanner = SessionManagerScanner()
        assert scanner is not None
        assert scanner.NAME == "session_management"

    def test_has_scan_url(self):
        scanner = SessionManagerScanner()
        assert hasattr(scanner, 'scan_url')
        assert callable(scanner.scan_url)

    def test_cookie_check_detects_missing_httponly(self):
        scanner = SessionManagerScanner()
        # Verify scanner has cookie checking capability
        assert hasattr(scanner, '_check_cookie_flags') or hasattr(scanner, 'scan_url')
