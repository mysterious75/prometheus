"""OSINT Credential Finder - Find usernames, emails, social profiles across platforms."""

import asyncio
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from ..utils.logger import logger


@dataclass
class Profile:
    """Found profile on a platform."""
    platform: str
    url: str
    username: str
    exists: bool
    display_name: str = ""
    bio: str = ""
    followers: int = 0
    profile_pic: str = ""
    verified: bool = False


@dataclass
class EmailResult:
    """Email search result."""
    email: str
    source: str
    name: str = ""
    breach_count: int = 0


class OSINTFinder:
    """Finds usernames, emails, social profiles across the internet."""

    # Platforms to check for username
    PLATFORMS = {
        "github": "https://github.com/{username}",
        "twitter": "https://x.com/{username}",
        "instagram": "https://www.instagram.com/{username}/",
        "linkedin": "https://www.linkedin.com/in/{username}",
        "youtube": "https://www.youtube.com/@{username}",
        "tiktok": "https://www.tiktok.com/@{username}",
        "reddit": "https://www.reddit.com/user/{username}",
        "pinterest": "https://www.pinterest.com/{username}/",
        "medium": "https://medium.com/@{username}",
        "devto": "https://dev.to/{username}",
        "gitlab": "https://gitlab.com/{username}",
        "stackoverflow": "https://stackoverflow.com/users/?tab=Accounts&SearchTerm={username}",
        "hackerone": "https://hackerone.com/{username}",
        "bugcrowd": "https://bugcrowd.com/{username}",
        "tryhackme": "https://tryhackme.com/p/{username}",
        "hackthebox": "https://app.hackthebox.com/users/{username}",
        "keybase": "https://keybase.io/{username}",
        "twitch": "https://www.twitch.tv/{username}",
        "discord": "https://discord.com/{username}",
        "telegram": "https://t.me/{username}",
    }

    # Email breach check services
    EMAIL_CHECKERS = [
        "https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
    ]

    def __init__(self):
        self.found_profiles: List[Profile] = []
        self.found_emails: List[EmailResult] = []
        self.client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    def find_username(self, username: str, platforms: Optional[List[str]] = None) -> List[Profile]:
        """Find a username across all platforms."""
        logger.info(f"[*] Searching username: {username}")
        platforms = platforms or list(self.PLATFORMS.keys())

        results = []
        for platform in platforms:
            if platform not in self.PLATFORMS:
                continue

            url = self.PLATFORMS[platform].format(username=username)
            try:
                response = self.client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })

                exists = response.status_code == 200
                # Some platforms return 200 even for non-existent users
                if platform == "github" and "Not Found" in response.text:
                    exists = False
                elif platform == "twitter" and "doesn't exist" in response.text:
                    exists = False

                profile = Profile(
                    platform=platform,
                    url=url,
                    username=username,
                    exists=exists
                )

                if exists:
                    # Try to extract display name
                    title_match = re.search(r"<title>(.*?)</title>", response.text)
                    if title_match:
                        profile.display_name = title_match.group(1).split(" (")[0].strip()

                    logger.info(f"  [+] Found on {platform}: {url}")
                else:
                    logger.info(f"  [-] Not found on {platform}")

                results.append(profile)
                self.found_profiles.append(profile)

            except Exception as e:
                logger.debug(f"  [!] Error checking {platform}: {e}")
                continue

        return results

    def find_emails(self, domain: str) -> List[str]:
        """Find emails associated with a domain."""
        logger.info(f"[*] Searching emails for domain: {domain}")
        emails = set()

        # Check common email patterns on the domain
        try:
            response = self.client.get(f"https://{domain}")
            # Extract emails from HTML
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found = re.findall(email_pattern, response.text)
            emails.update(found)
        except Exception:
            pass

        # Check /robots.txt for email paths
        try:
            response = self.client.get(f"https://{domain}/robots.txt")
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found = re.findall(email_pattern, response.text)
            emails.update(found)
        except Exception:
            pass

        # Check /sitemap.xml
        try:
            response = self.client.get(f"https://{domain}/sitemap.xml")
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            found = re.findall(email_pattern, response.text)
            emails.update(found)
        except Exception:
            pass

        return list(emails)

    def find_leaked_emails(self, email: str) -> List[Dict]:
        """Check if email has been in data breaches."""
        logger.info(f"[*] Checking breaches for: {email}")
        breaches = []

        try:
            # Check via API (requires API key for full results)
            response = self.client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "User-Agent": "Prometheus-OSINT",
                    "hibp-api-key": ""  # Free tier limited
                }
            )
            if response.status_code == 200:
                data = response.json()
                for breach in data:
                    breaches.append({
                        "name": breach.get("Name", ""),
                        "date": breach.get("BreachDate", ""),
                        "data_classes": breach.get("DataClasses", []),
                        "pwn_count": breach.get("PwnCount", 0),
                    })
                logger.info(f"  [!] Found in {len(breaches)} breaches")
        except Exception:
            pass

        return breaches

    def find_subdomains(self, domain: str) -> List[str]:
        """Find subdomains using crt.sh certificate transparency."""
        logger.info(f"[*] Finding subdomains via CT logs: {domain}")
        subdomains = set()

        try:
            response = self.client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
        except Exception:
            pass

        return sorted(subdomains)

    def gather_target_info(self, target: str) -> Dict[str, Any]:
        """Complete OSINT on a target - subdomains, emails, usernames."""
        logger.info(f"[bold cyan]Gathering OSINT on: {target}[/bold cyan]")

        info = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "emails": [],
            "profiles": [],
            "tech_stack": [],
            "headers": {},
        }

        # Find subdomains
        info["subdomains"] = self.find_subdomains(target)

        # Find emails
        info["emails"] = self.find_emails(target)

        # Check headers for tech stack
        try:
            response = self.client.get(f"https://{target}")
            info["headers"] = dict(response.headers)
            # Detect technologies
            server = response.headers.get("Server", "")
            powered_by = response.headers.get("X-Powered-By", "")
            if server:
                info["tech_stack"].append(f"Server: {server}")
            if powered_by:
                info["tech_stack"].append(f"Framework: {powered_by}")
        except Exception:
            pass

        # Try common usernames based on domain
        base_name = target.split(".")[0]
        common_names = [base_name, f"{base_name}dev", f"{base_name}admin", "admin", "root", "test"]
        for name in common_names[:3]:  # Limit to avoid too many requests
            profiles = self.find_username(name, platforms=["github", "twitter", "linkedin"])
            info["profiles"].extend([
                {"platform": p.platform, "url": p.url, "exists": p.exists}
                for p in profiles if p.exists
            ])

        logger.info(f"[green]OSINT complete: {len(info['subdomains'])} subdomains, {len(info['emails'])} emails[/green]")
        return info

    def generate_wordlist(self, target: str, info: Dict) -> List[str]:
        """Generate smart wordlist based on OSINT info."""
        words = set()

        # Add target name variations
        base = target.split(".")[0]
        words.add(base)
        words.add(f"{base}123")
        words.add(f"{base}!")
        words.add(f"{base}@2024")
        words.add(f"{base}@2025")
        words.add(f"{base}2024")
        words.add(f"{base}2025")
        words.add(f"password{base}")
        words.add(f"{base}password")

        # Add found names
        for profile in info.get("profiles", []):
            words.add(profile.get("username", ""))

        # Add found emails as potential passwords
        for email in info.get("emails", []):
            name = email.split("@")[0]
            words.add(name)
            words.add(f"{name}123")
            words.add(f"{name}!")

        # Common patterns
        common = [
            "admin", "password", "123456", "qwerty", "letmein",
            "welcome", "monkey", "dragon", "master", "login",
            "admin123", "root", "toor", "pass", "test",
        ]
        words.update(common)

        words.discard("")
        return sorted(words)

    def get_stats(self) -> Dict:
        return {
            "profiles_found": len([p for p in self.found_profiles if p.exists]),
            "profiles_checked": len(self.found_profiles),
            "platforms": len(self.PLATFORMS),
        }
