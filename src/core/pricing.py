"""Pricing Model — global market, USD pricing.

Free tier for community, paid tiers for teams and enterprises.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class PricingTier:
    """A pricing tier."""
    name: str
    price_monthly: float  # USD
    price_yearly: float  # USD (discounted)
    features: List[str]
    limits: Dict[str, Any]
    target_user: str


# Pricing tiers
TIERS = {
    "free": PricingTier(
        name="Community (Free)",
        price_monthly=0,
        price_yearly=0,
        features=[
            "10 URLs per scan",
            "5 vulnerability scanners",
            "Basic report (Markdown)",
            "Community support",
            "CLI only",
            "No API access",
        ],
        limits={
            "urls_per_scan": 10,
            "scans_per_month": 5,
            "scanners": ["sqli", "xss", "headers", "secrets", "cors"],
            "report_format": "markdown",
            "continuous": False,
            "api_access": False,
            "auto_fix": False,
        },
        target_user="Individual security researchers, students, hobbyists",
    ),
    "pro": PricingTier(
        name="Pro",
        price_monthly=19,
        price_yearly=190,
        features=[
            "Unlimited URLs per scan",
            "All 15 vulnerability scanners",
            "Full reports (Markdown + JSON)",
            "GraphQL/API security testing",
            "JWT analysis",
            "Subdomain discovery",
            "Cloud bucket scanning (S3/Azure/GCP)",
            "Email support",
            "CLI + API access",
        ],
        limits={
            "urls_per_scan": -1,  # unlimited
            "scans_per_month": 50,
            "scanners": "all",
            "report_format": "all",
            "continuous": False,
            "api_access": True,
            "auto_fix": False,
        },
        target_user="Freelance pentesters, small security teams",
    ),
    "team": PricingTier(
        name="Team",
        price_monthly=99,
        price_yearly=990,
        features=[
            "Everything in Pro",
            "Continuous scanning (scheduled)",
            "Auto-fix PR generation",
            "Multi-session BOLA/IDOR testing",
            "Internal network scanning",
            "Self-learning engine",
            "Knowledge base access",
            "Slack/Discord notifications",
            "Priority support",
            "Up to 5 team members",
        ],
        limits={
            "urls_per_scan": -1,
            "scans_per_month": 200,
            "scanners": "all",
            "report_format": "all",
            "continuous": True,
            "api_access": True,
            "auto_fix": True,
            "team_members": 5,
        },
        target_user="Security teams at startups and mid-size companies",
    ),
    "enterprise": PricingTier(
        name="Enterprise",
        price_monthly=299,
        price_yearly=2990,
        features=[
            "Everything in Team",
            "Unlimited team members",
            "SSO/SAML integration",
            "Compliance reports (OWASP, SOC 2, PCI-DSS)",
            "Custom playbooks",
            "Dedicated support",
            "On-premise deployment option",
            "SLA guarantee",
            "Custom integrations",
        ],
        limits={
            "urls_per_scan": -1,
            "scans_per_month": -1,
            "scanners": "all",
            "report_format": "all",
            "continuous": True,
            "api_access": True,
            "auto_fix": True,
            "team_members": -1,
            "compliance_reports": True,
            "on_premise": True,
        },
        target_user="Large enterprises, financial institutions, government",
    ),
}


def get_tier(name: str) -> PricingTier:
    """Get a pricing tier by name."""
    return TIERS.get(name, TIERS["free"])


def get_all_tiers() -> Dict[str, PricingTier]:
    """Get all pricing tiers."""
    return TIERS


def format_pricing_table() -> str:
    """Format a pricing table for display."""
    lines = ["\n  Pricing (USD):", "  " + "=" * 60]
    for name, tier in TIERS.items():
        price = f"${tier.price_monthly}/mo" if tier.price_monthly > 0 else "Free"
        yearly = f"(${tier.price_yearly}/yr)" if tier.price_yearly > 0 else ""
        lines.append(f"  {tier.name:20} {price:12} {yearly}")
        lines.append(f"  {'':20} {tier.target_user}")
        lines.append(f"  {'':20} {', '.join(tier.features[:3])}...")
        lines.append(f"  {'':20} {'-' * 40}")
    return "\n".join(lines)
