"""
Configuration management for Userhunt CLI.
Supports env vars, config files, and secure API key storage.
Built-in free AI providers: Groq, Gemini, Cerebras, OpenRouter.
"""
import os
import json
import stat
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class AIProvider(str, Enum):
    # Built-in free providers (no card required)
    GROQ_FREE = "groq_free"
    GEMINI_FREE = "gemini_free"
    CEREBRAS_FREE = "cerebras_free"
    OPENROUTER_FREE = "openrouter_free"
    # Paid / custom providers
    GROQ = "groq"
    OPENAI = "openai"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"
    CUSTOM = "custom"


# Built-in provider configurations — all free, no credit card required
BUILTIN_PROVIDERS = {
    AIProvider.GROQ_FREE: {
        "name": "Groq Free (Fastest)",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "description": "Free tier: 30 RPM, 1000 req/day. No card required. Fastest inference.",
        "requires_key": True,  # Need free API key from console.groq.com
    },
    AIProvider.GEMINI_FREE: {
        "name": "Google Gemini Free",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-2.0-flash",
        "description": "Free tier: 1500 req/day, 10 RPM. No card required. Google account only.",
        "requires_key": True,  # Need free key from ai.google.dev
    },
    AIProvider.CEREBRAS_FREE: {
        "name": "Cerebras Free",
        "base_url": "https://api.cerebras.ai/v1",
        "model": "llama-3.3-70b",
        "description": "Free tier: 5 RPM, 1M tokens/day. No card required. Great for long context.",
        "requires_key": True,  # Need free key from cloud.cerebras.ai
    },
    AIProvider.OPENROUTER_FREE: {
        "name": "OpenRouter Free Models",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "description": "Free tier: 20 RPM, 50 req/day (1000 after $10 credit). No card for free models.",
        "requires_key": True,  # Need free key from openrouter.ai
    },
    AIProvider.GROQ: {
        "name": "Groq (Paid)",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "description": "Paid Groq with higher limits.",
        "requires_key": True,
    },
    AIProvider.OPENAI: {
        "name": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "description": "OpenAI GPT models. Requires API key.",
        "requires_key": True,
    },
    AIProvider.GEMINI: {
        "name": "Google Gemini (Paid)",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-2.0-flash",
        "description": "Google Gemini with paid tier limits.",
        "requires_key": True,
    },
    AIProvider.OPENROUTER: {
        "name": "OpenRouter (Paid)",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "auto",
        "description": "OpenRouter with 50+ models. Pay per token.",
        "requires_key": True,
    },
    AIProvider.CUSTOM: {
        "name": "Custom OpenAI-Compatible",
        "base_url": "",
        "model": "",
        "description": "Any OpenAI-compatible API endpoint.",
        "requires_key": True,
    },
}


@dataclass
class AIConfig:
    enabled: bool = False
    provider: AIProvider = AIProvider.GROQ_FREE  # Default to fastest free option
    api_key: str = ""
    base_url: str = "https://api.groq.com/openai/v1"
    model: str = "llama-3.3-70b-versatile"
    temperature: float = 0.1
    max_tokens: int = 900
    timeout: int = 60
    # No limits — full accuracy
    max_calls_per_round: int = 0  # 0 = unlimited
    max_input_chars: int = 0  # 0 = unlimited
    max_final_input_chars: int = 0  # 0 = unlimited
    retry_delay: int = 5
    calls_made: int = 0

    def mask_key(self) -> str:
        if not self.api_key:
            return "***"
        return "*" * (len(self.api_key) - 4) + self.api_key[-4:]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["provider"] = self.provider.value
        d.pop("calls_made", None)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "AIConfig":
        data = dict(data)
        data.pop("calls_made", None)
        if "provider" in data and isinstance(data["provider"], str):
            try:
                data["provider"] = AIProvider(data["provider"])
            except ValueError:
                data["provider"] = AIProvider.CUSTOM
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class HuntConfig:
    workspace: Path = field(default_factory=lambda: Path("./userhunt_workspace"))
    max_rounds: int = 8
    # No caps — full accuracy
    max_hits: int = 0  # 0 = unlimited
    max_pivot_log: int = 0  # 0 = unlimited
    max_notes: int = 0  # 0 = unlimited
    max_tool_output_kb: int = 0  # 0 = no truncation
    link_visit_cap: int = 0  # 0 = unlimited
    max_usernames_per_round: int = 0  # 0 = unlimited
    max_emails_per_round: int = 0  # 0 = unlimited
    # Storage
    compress_output: bool = True  # gzip JSON/PDF output
    disk_warn_mb: int = 2000
    disk_abort_mb: int = 500
    tool_timeout: int = 0  # 0 = no timeout (runs to completion)
    github_token: str = ""
    debug: bool = False
    # Upgrade source
    upgrade_repo: str = "Real-Nightmare/Userhunt-CLI"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["workspace"] = str(self.workspace)
        return d


class Config:
    def __init__(self):
        self.ai = AIConfig()
        self.hunt = HuntConfig()
        self._config_path = Path("./userhunt_workspace/config.json")
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        self._loaded = True

        # Env var priority: AI_API_KEY/AI_BASE_URL/AI_MODEL, then OPENAI_API_KEY
        env_key = os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY")
        env_base = os.getenv("AI_BASE_URL")
        env_model = os.getenv("AI_MODEL")
        env_provider = os.getenv("AI_PROVIDER")

        if env_key:
            self.ai.api_key = env_key.strip().strip('"').strip("'")
            self.ai.enabled = True
        if env_base:
            self.ai.base_url = env_base.strip().strip('"').strip("'")
        if env_model:
            self.ai.model = env_model.strip().strip('"').strip("'")
        if env_provider:
            try:
                self.ai.provider = AIProvider(env_provider.strip())
            except ValueError:
                pass

        # Load from config.json if present
        if self._config_path.exists():
            try:
                with open(self._config_path, "r") as f:
                    data = json.load(f)
                if "ai" in data:
                    saved = AIConfig.from_dict(data["ai"])
                    if saved.api_key and not self.ai.api_key:
                        self.ai = saved
                        self.ai.enabled = True
                    elif saved.api_key and self.ai.api_key:
                        # env takes priority but keep other fields from file
                        self.ai.base_url = saved.base_url
                        self.ai.model = saved.model
                        self.ai.provider = saved.provider
                if "hunt" in data:
                    for k, v in data["hunt"].items():
                        if k == "workspace":
                            self.hunt.workspace = Path(v)
                        elif hasattr(self.hunt, k):
                            setattr(self.hunt, k, v)
            except Exception:
                pass

    def save_ai(self) -> None:
        """Save AI config to disk with restricted permissions."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {}
        if self._config_path.exists():
            try:
                with open(self._config_path, "r") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        data["ai"] = self.ai.to_dict()
        tmp = self._config_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        tmp.replace(self._config_path)
        try:
            os.chmod(self._config_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def save_hunt(self) -> None:
        """Save hunt config to disk."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {}
        if self._config_path.exists():
            try:
                with open(self._config_path, "r") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        data["hunt"] = self.hunt.to_dict()
        tmp = self._config_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        tmp.replace(self._config_path)

    @property
    def github_token(self) -> str:
        return os.getenv("GITHUB_TOKEN", self.hunt.github_token)
