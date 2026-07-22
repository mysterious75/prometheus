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

    # API Keys - all providers
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

    # DeepSeek (PRIMARY)
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")

    # Google Gemini (CONSCIOUSNESS - 3 keys for rotation)
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY_1", os.getenv("GEMINI_API_KEY", ""))
    GEMINI_API_KEY_1 = os.getenv("GEMINI_API_KEY_1", "")
    GEMINI_API_KEY_2 = os.getenv("GEMINI_API_KEY_2", "")
    GEMINI_API_KEY_3 = os.getenv("GEMINI_API_KEY_3", "")

    # OpenCode
    OPENCODE_GO_API_KEY = os.getenv("OPENCODE_GO_API_KEY", "")
    OPENCODE_ZEN_API_KEY = os.getenv("OPENCODE_ZEN_API_KEY", "")

    # Other providers
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    QWEN_API_KEY = os.getenv("QWEN_API_KEY", "")
    KIMI_API_KEY = os.getenv("KIMI_API_KEY", "")
    GLM_API_KEY = os.getenv("GLM_API_KEY", "")
    XIAOMI_API_KEY = os.getenv("XIAOMI_API_KEY", "")
    NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

    # Models
    OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    # Database
    SUPABASE_URL = os.getenv("SUPABASE_URL", "")
    SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
    CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

    # App
    APP_NAME = os.getenv("APP_NAME", "Prometheus")
    APP_VERSION = os.getenv("APP_VERSION", "2.0.0")
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
        """Validate that at least one API key is present."""
        keys = [
            cls.DEEPSEEK_API_KEY,
            cls.GEMINI_API_KEY_1, cls.GEMINI_API_KEY_2, cls.GEMINI_API_KEY_3,
            cls.OPENCODE_GO_API_KEY, cls.OPENCODE_ZEN_API_KEY,
            cls.OPENAI_API_KEY, cls.ANTHROPIC_API_KEY,
            cls.QWEN_API_KEY, cls.KIMI_API_KEY, cls.GLM_API_KEY,
            cls.XIAOMI_API_KEY, cls.NVIDIA_API_KEY, cls.OPENROUTER_API_KEY,
        ]
        if not any(keys):
            print("[ERROR] No API keys found! Add at least one key to .env")
            return False
        return True

    @classmethod
    def get_available_keys(cls) -> list:
        """List which provider keys are set."""
        providers = []
        if cls.DEEPSEEK_API_KEY:
            providers.append("deepseek")
        if cls.GEMINI_API_KEY_1:
            providers.append("gemini_1")
        if cls.GEMINI_API_KEY_2:
            providers.append("gemini_2")
        if cls.GEMINI_API_KEY_3:
            providers.append("gemini_3")
        if cls.OPENCODE_GO_API_KEY:
            providers.append("opencode_go")
        if cls.OPENCODE_ZEN_API_KEY:
            providers.append("opencode_zen")
        if cls.OPENAI_API_KEY:
            providers.append("openai")
        if cls.ANTHROPIC_API_KEY:
            providers.append("anthropic")
        if cls.QWEN_API_KEY:
            providers.append("qwen")
        if cls.KIMI_API_KEY:
            providers.append("kimi")
        if cls.GLM_API_KEY:
            providers.append("glm")
        if cls.XIAOMI_API_KEY:
            providers.append("xiaomi")
        if cls.NVIDIA_API_KEY:
            providers.append("nvidia")
        if cls.OPENROUTER_API_KEY:
            providers.append("openrouter")
        return providers


config = Config()
