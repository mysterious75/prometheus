"""Auto-Evolution module - Self-improving code system."""

from .scanner import GitHubScanner
from .self_modifier import SelfModifier

__all__ = ["GitHubScanner", "SelfModifier"]
