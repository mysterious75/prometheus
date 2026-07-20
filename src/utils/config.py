"""Configuration loader for Project Prometheus."""

import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


class Config:
    """Central configuration class."""

    # API Keys
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

    # Models
    OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    # Database
    SUPABASE_URL = os.getenv("SUPABASE_URL", "")
    SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
    CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

    # App
    APP_NAME = os.getenv("APP_NAME", "Prometheus")
    APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    @classmethod
    def get_model_config(cls) -> dict:
        """Load model configurations from config/models.json."""
        config_path = Path(__file__).parent.parent.parent / "config" / "models.json"
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        return {}

    @classmethod
    def validate(cls) -> bool:
        """Validate that required config is present."""
        if not cls.GEMINI_API_KEY and not cls.OPENROUTER_API_KEY:
            print("[ERROR] No API keys found! Set GEMINI_API_KEY or OPENROUTER_API_KEY in .env")
            return False
        return True


config = Config()
