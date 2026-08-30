"""
Configuration management for USERHUNT CLI.
Supports env vars, config files, and secure API key storage.
"""
import os
import json
import stat
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class AIProvider(str, Enum):
    GROQ = "groq"
    OPENAI = "openai"
    GEMINI = "gemini"
    OPENROUTER = "openrouter"
    CUSTOM = "custom"


@dataclass
class AIConfig:
    enabled: bool = False
    provider: AIProvider = AIProvider.GROQ
    api_key: str = ""
    base_url: str = "https://api.groq.com/openai/v1"
    model: str = "llama-3.3-70b-versatile"
    temperature: float = 0.1
    max_tokens: int = 900
    timeout: int = 60
    max_calls_per_round: int = 40
    max_input_chars: int = 12000
    max_final_input_chars: int = 24000
    retry_delay: int = 5
    calls_made: int = 0

    def mask_key(self) -> str:
        if not self.api_key:
            return "***"
        return "*" * (len(self.api_key) - 4) + self.api_key[-4:]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["provider"] = self.provider.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "AIConfig":
        if "provider" in data and isinstance(data["provider"], str):
            data = dict(data)
            data["provider"] = AIProvider(data["provider"])
        return cls(**data)


@dataclass
class HuntConfig:
    workspace: Path = field(default_factory=lambda: Path("./username_hunt_workspace"))
    max_rounds: int = 8
    max_hits: int = 3000
    max_pivot_log: int = 2000
    max_notes: int = 1000
    max_tool_output_kb: int = 200
    link_visit_cap: int = 60
    max_usernames_per_round: int = 40
    max_emails_per_round: int = 20
    disk_warn_mb: int = 2000
    disk_abort_mb: int = 500
    tool_timeout: int = 420
    github_token: str = ""
    debug: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["workspace"] = str(self.workspace)
        return d


class Config:
    def __init__(self):
        self.ai = AIConfig()
        self.hunt = HuntConfig()
        self._config_path = Path("./username_hunt_workspace/config.json")
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        env_key = os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY")
        env_base = os.getenv("AI_BASE_URL")
        env_model = os.getenv("AI_MODEL")
        if env_key:
            self.ai.api_key = env_key.strip().strip('"').strip("'")
            self.ai.enabled = True
        if env_base:
            self.ai.base_url = env_base.strip().strip('"').strip("'")
        if env_model:
            self.ai.model = env_model.strip().strip('"').strip("'")
        if self.ai.api_key and not env_base:
            if self.ai.provider == AIProvider.GROQ:
                self.ai.base_url = "https://api.groq.com/openai/v1"
            elif self.ai.provider == AIProvider.OPENAI:
                self.ai.base_url = "https://api.openai.com/v1"
        if self._config_path.exists():
            try:
                with open(self._config_path, "r") as f:
                    data = json.load(f)
                if "ai" in data:
                    saved = AIConfig.from_dict(data["ai"])
                    if saved.api_key and not self.ai.api_key:
                        self.ai = saved
                        self.ai.enabled = True
                if "hunt" in data:
                    for k, v in data["hunt"].items():
                        if hasattr(self.hunt, k):
                            setattr(self.hunt, k, v)
            except Exception:
                pass

    def save_ai(self) -> None:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
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

    @property
    def github_token(self) -> str:
        return os.getenv("GITHUB_TOKEN", self.hunt.github_token)
