"""Scanner Package — real vulnerability detection with validation.

Every finding must be VERIFIED. No false positives.
"""

from .crawler import WebCrawler, CrawlResult, Endpoint, Form
from .findings import Finding, ScanResult
from .sqli import SQLiScanner
from .xss import XSSScanner
from .ssrf import SSRFScanner
from .cmdi import CMDiScanner
from .idor import IDORScanner
from .secrets import SecretsScanner
from .headers import HeadersScanner
from .cors import CORSScanner
from .redirect import RedirectScanner
from .traversal import TraversalScanner
from .smuggling import SmugglingScanner
from .xxe import XXEScanner
from .ssti import SSTIScanner
from .race import RaceConditionScanner
from .auth import AuthBypassScanner
from .runner import ScanRunner

__all__ = [
    "WebCrawler", "CrawlResult", "Endpoint", "Form",
    "Finding", "ScanResult",
    "SQLiScanner", "XSSScanner", "SSRFScanner", "CMDiScanner",
    "IDORScanner", "SecretsScanner", "HeadersScanner", "CORSScanner",
    "RedirectScanner", "TraversalScanner", "SmugglingScanner",
    "XXEScanner", "SSTIScanner", "RaceConditionScanner",
    "AuthBypassScanner", "ScanRunner",
]
