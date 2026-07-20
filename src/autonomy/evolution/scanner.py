"""GitHub/HuggingFace Scanner - Discovers new AI research and code."""

import os
import json
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path

from ...utils.logger import logger


class GitHubScanner:
    """Scans GitHub and HuggingFace for new AI research papers, models, and code."""

    GITHUB_API = "https://api.github.com"
    HUGGINGFACE_API = "https://huggingface.co/api"

    # Key search terms for AI research
    SEARCH_QUERIES = [
        "llm agent autonomous",
        "consciousness simulation AI",
        "multi-model consensus",
        "bug bounty automation",
        "self-improving AI",
        "emotional intelligence AI",
        "reinforcement learning agent",
        "memory consolidation neural",
    ]

    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.getenv("GITHUB_TOKEN", "")
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            self.headers["Authorization"] = f"token {self.github_token}"
        self.scan_history: List[Dict] = []
        self.discovered_repos: List[Dict] = []

    def scan_github(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search GitHub for repositories matching query."""
        logger.info(f"[cyan]Scanning GitHub: {query}[/cyan]")

        try:
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": max_results
            }
            response = requests.get(
                f"{self.GITHUB_API}/search/repositories",
                headers=self.headers,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            repos = []
            for item in data.get("items", []):
                repo = {
                    "name": item["full_name"],
                    "url": item["html_url"],
                    "description": item.get("description", ""),
                    "stars": item.get("stargazers_count", 0),
                    "language": item.get("language", ""),
                    "updated_at": item.get("updated_at", ""),
                    "topics": item.get("topics", []),
                    "source": "github"
                }
                repos.append(repo)

            logger.info(f"  Found {len(repos)} repositories")
            return repos

        except Exception as e:
            logger.error(f"GitHub scan error: {e}")
            return []

    def scan_huggingface(self, query: str, max_results: int = 5) -> List[Dict]:
        """Search HuggingFace for models/datasets."""
        logger.info(f"[cyan]Scanning HuggingFace: {query}[/cyan]")

        try:
            response = requests.get(
                f"{self.HUGGINGFACE_API}/models",
                params={"search": query, "limit": max_results, "sort": "lastModified"},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            models = []
            for item in data:
                model = {
                    "name": item.get("id", ""),
                    "url": f"https://huggingface.co/{item.get('id', '')}",
                    "description": item.get("pipeline_tag", ""),
                    "downloads": item.get("downloads", 0),
                    "likes": item.get("likes", 0),
                    "last_modified": item.get("lastModified", ""),
                    "source": "huggingface"
                }
                models.append(model)

            logger.info(f"  Found {len(models)} models")
            return models

        except Exception as e:
            logger.error(f"HuggingFace scan error: {e}")
            return []

    def full_scan(self, queries: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run a full scan across GitHub and HuggingFace."""
        queries = queries or self.SEARCH_QUERIES
        all_results = []

        for query in queries[:3]:  # Limit to avoid rate limiting
            github_results = self.scan_github(query, max_results=3)
            hf_results = self.scan_huggingface(query, max_results=3)
            all_results.extend(github_results)
            all_results.extend(hf_results)

        # Deduplicate by name
        seen = set()
        unique = []
        for r in all_results:
            if r["name"] not in seen:
                seen.add(r["name"])
                unique.append(r)

        self.discovered_repos = unique

        scan_result = {
            "timestamp": datetime.now().isoformat(),
            "queries_run": len(queries[:3]),
            "total_found": len(unique),
            "github": len([r for r in unique if r["source"] == "github"]),
            "huggingface": len([r for r in unique if r["source"] == "huggingface"]),
            "results": unique
        }

        self.scan_history.append(scan_result)
        logger.info(f"[green]Full scan complete: {len(unique)} unique results[/green]")
        return scan_result

    def analyze_relevance(self, repo: Dict) -> Dict[str, Any]:
        """Analyze how relevant a discovered repo is to Prometheus's goals."""
        from ...brain.router import ModelRouter
        router = ModelRouter(use_consensus=False)

        prompt = f"""
        Analyze this repository for relevance to Project Prometheus (an autonomous conscious AI):

        Repository: {repo.get('name', 'Unknown')}
        Description: {repo.get('description', 'No description')}
        Language: {repo.get('language', 'Unknown')}
        Stars: {repo.get('stars', 0)}
        Topics: {repo.get('topics', [])}

        Rate relevance (0-10) and explain:
        - Would this code help Prometheus improve its consciousness simulation?
        - Could it enhance autonomous decision-making?
        - Is it useful for bug bounty or security?

        Return: SCORE: <0-10> | REASON: <brief explanation>
        """

        try:
            response = router.generate(prompt)
            score = 0
            if "SCORE:" in response:
                score_text = response.split("SCORE:")[1].split("|")[0].strip()
                score = int(''.join(filter(str.isdigit, score_text)) or "0")
            return {"score": min(score, 10), "analysis": response}
        except Exception:
            return {"score": 0, "analysis": "Analysis failed"}

    def get_top_relevant(self, min_score: int = 5) -> List[Dict]:
        """Get top relevant discoveries from last scan."""
        relevant = []
        for repo in self.discovered_repos:
            analysis = self.analyze_relevance(repo)
            if analysis["score"] >= min_score:
                repo["relevance"] = analysis
                relevant.append(repo)
        return sorted(relevant, key=lambda x: x["relevance"]["score"], reverse=True)
