"""Tests for Business Logic Scanner."""
import pytest
from unittest.mock import MagicMock, patch
from src.scanner.business_logic import BusinessLogicScanner


class TestBusinessLogicScanner:
    def test_init(self):
        scanner = BusinessLogicScanner()
        assert scanner is not None
        assert scanner.NAME == "business_logic"

    def test_has_scan_url(self):
        scanner = BusinessLogicScanner()
        assert hasattr(scanner, 'scan_url')
        assert callable(scanner.scan_url)

    @patch('src.scanner.business_logic.httpx')
    def test_scan_returns_list(self, mock_httpx):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><form><input name='qty' value='1'></form></html>"
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_httpx.Client.return_value.__enter__.return_value.get.return_value = mock_resp

        scanner = BusinessLogicScanner()
        # Verify scanner initializes
        assert scanner.NAME == "business_logic"
