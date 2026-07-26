"""Prometheus — AI-Powered Autonomous Security Testing Platform."""

from setuptools import setup, find_packages
from pathlib import Path

here = Path(__file__).parent
long_description = (here / "README.md").read_text(encoding="utf-8") if (here / "README.md").exists() else ""

setup(
    name="prometheus-security",
    version="3.0.0",
    description="AI-powered autonomous security testing platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mysterious75/prometheus",
    author="mysterious75",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security pentest vulnerability scanner ai cybersecurity bugbounty",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "google-generativeai>=0.8.0",
        "openai>=1.50.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.0.0",
        "requests>=2.31.0",
        "httpx[http2]>=0.27.0",
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "dnspython>=2.4.0",
        "python-whois>=0.9.4",
        "rich>=13.0.0",
    ],
    extras_require={
        "full": [
            "chromadb>=0.5.0",
            "sentence-transformers>=3.0.0",
            "playwright>=1.50.0",
            "networkx>=3.0",
            "pytest>=8.0.0",
        ],
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=5.0.0",
            "flake8",
        ],
    },
    entry_points={
        "console_scripts": [
            "prometheus=src.entry:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yml", "*.yaml", "*.json", "*.txt", "*.md"],
    },
)
