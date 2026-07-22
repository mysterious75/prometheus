"""Configuration loader - auto-detects any API key available."""

import os
import json
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


class Config:
    """Auto-detect configuration from .env - works with any keys."""

    # App
    APP_NAME = os.getenv("APP_NAME", "Prometheus")
    APP_VERSION = os.getenv("APP_VERSION", "2.0.0")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    USE_CONSENSUS = os.getenv("USE_CONSENSUS", "false").lower() == "true"

    # Database
    CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

    @classmethod
    def get_model_config(cls) -> dict:
        config_path = Path(__file__).parent.parent.parent / "config" / "models.json"
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        return {}

    @classmethod
    def get_all_keys(cls) -> dict:
        """Find ALL API keys in .env - returns {provider_name: {key, base_url, model}}."""
        providers = {}

        # Named providers with known base URLs
        known_providers = {
            "deepseek": {
                "key_env": "DEEPSEEK_API_KEY",
                "base_url_env": "DEEPSEEK_BASE_URL",
                "model_env": "DEEPSEEK_MODEL",
                "default_base": "https://api.deepseek.com/v1",
                "default_model": "deepseek-chat",
            },
            "gemini_1": {
                "key_env": "GEMINI_API_KEY_1",
                "base_url_env": None,
                "model_env": "GEMINI_MODEL",
                "default_base": "",
                "default_model": "gemini-2.0-flash",
                "type": "gemini",
            },
            "gemini_2": {
                "key_env": "GEMINI_API_KEY_2",
                "base_url_env": None,
                "model_env": None,
                "default_base": "",
                "default_model": "gemini-2.0-flash",
                "type": "gemini",
            },
            "gemini_3": {
                "key_env": "GEMINI_API_KEY_3",
                "base_url_env": None,
                "model_env": None,
                "default_base": "",
                "default_model": "gemini-2.0-flash",
                "type": "gemini",
            },
            "opencode_go": {
                "key_env": "OPENCODE_GO_API_KEY",
                "base_url_env": "OPENCODE_GO_BASE_URL",
                "model_env": "OPENCODE_GO_MODEL",
                "default_base": "",
                "default_model": "",
            },
            "opencode_zen": {
                "key_env": "OPENCODE_ZEN_API_KEY",
                "base_url_env": "OPENCODE_ZEN_BASE_URL",
                "model_env": "OPENCODE_ZEN_MODEL",
                "default_base": "",
                "default_model": "",
            },
            "openai": {
                "key_env": "OPENAI_API_KEY",
                "base_url_env": None,
                "model_env": "OPENAI_MODEL",
                "default_base": "https://api.openai.com/v1",
                "default_model": "gpt-4o-mini",
            },
            "anthropic": {
                "key_env": "ANTHROPIC_API_KEY",
                "base_url_env": None,
                "model_env": "ANTHROPIC_MODEL",
                "default_base": "https://api.anthropic.com/v1",
                "default_model": "claude-3-5-haiku-20241022",
                "type": "anthropic",
            },
            "qwen": {
                "key_env": "QWEN_API_KEY",
                "base_url_env": "QWEN_BASE_URL",
                "model_env": "QWEN_MODEL",
                "default_base": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                "default_model": "qwen-turbo",
            },
            "kimi": {
                "key_env": "KIMI_API_KEY",
                "base_url_env": "KIMI_BASE_URL",
                "model_env": "KIMI_MODEL",
                "default_base": "https://api.moonshot.cn/v1",
                "default_model": "moonshot-v1-8k",
            },
            "glm": {
                "key_env": "GLM_API_KEY",
                "base_url_env": "GLM_BASE_URL",
                "model_env": "GLM_MODEL",
                "default_base": "https://open.bigmodel.cn/api/paas/v4",
                "default_model": "glm-4-flash",
            },
            "xiaomi": {
                "key_env": "XIAOMI_API_KEY",
                "base_url_env": "XIAOMI_BASE_URL",
                "model_env": "XIAOMI_MODEL",
                "default_base": "",
                "default_model": "",
            },
            "nvidia": {
                "key_env": "NVIDIA_API_KEY",
                "base_url_env": "NVIDIA_BASE_URL",
                "model_env": "NVIDIA_MODEL",
                "default_base": "https://integrate.api.nvidia.com/v1",
                "default_model": "nvidia/llama-3.1-nemotron-70b-instruct",
            },
            "openrouter": {
                "key_env": "OPENROUTER_API_KEY",
                "base_url_env": None,
                "model_env": "OPENROUTER_MODEL",
                "default_base": "https://openrouter.ai/api/v1",
                "default_model": "meta-llama/llama-3.1-8b-instruct:free",
            },
        }

        # Scan for named providers
        for name, info in known_providers.items():
            key = os.getenv(info["key_env"], "")
            if not key:
                continue
            base_url = os.getenv(info.get("base_url_env", "") or "", info["default_base"])
            model = os.getenv(info.get("model_env", "") or "", info["default_model"])
            providers[name] = {
                "key": key,
                "base_url": base_url,
                "model": model,
                "type": info.get("type", "openai"),
            }

        # Check for CUSTOM provider
        custom_key = os.getenv("CUSTOM_API_KEY", "")
        if custom_key:
            custom_name = os.getenv("CUSTOM_NAME", "custom")
            providers[custom_name] = {
                "key": custom_key,
                "base_url": os.getenv("CUSTOM_BASE_URL", ""),
                "model": os.getenv("CUSTOM_MODEL", ""),
                "type": "openai",
            }

        # Scan for ANY env var ending with _API_KEY that we don't already know
        known_keys = {info["key_env"] for info in known_providers.values()}
        known_keys.add("CUSTOM_API_KEY")
        known_keys.add("GITHUB_TOKEN")

        for env_key, env_val in os.environ.items():
            if env_key.endswith("_API_KEY") and env_val and env_key not in known_keys:
                # Unknown provider - auto-detect
                provider_name = env_key.replace("_API_KEY", "").lower()
                base_url = os.getenv(f"{provider_name.upper()}_BASE_URL", "")
                model = os.getenv(f"{provider_name.upper()}_MODEL", "")
                providers[provider_name] = {
                    "key": env_val,
                    "base_url": base_url,
                    "model": model,
                    "type": "openai",
                }

        return providers

    @classmethod
    def validate(cls) -> bool:
        """Check if at least one key is available."""
        keys = cls.get_all_keys()
        if not keys:
            print("[ERROR] No API keys found! Add at least one key to .env")
            return False
        return True

    @classmethod
    def get_available_names(cls) -> list:
        return list(cls.get_all_keys().keys())


config = Config()
