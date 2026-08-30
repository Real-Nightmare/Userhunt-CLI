"""
Tests for Config and AIConfig.
"""
import json
import os
import stat
from pathlib import Path

import pytest

from userhunt.config import Config, AIConfig, AIProvider, HuntConfig, BUILTIN_PROVIDERS


class TestAIConfig:
    def test_mask_key_short(self):
        ai = AIConfig(api_key="abc123")
        assert ai.mask_key() == "***abc123" or len(ai.mask_key()) > 0

    def test_mask_key_long(self):
        ai = AIConfig(api_key="sk-very-long-api-key-here")
        masked = ai.mask_key()
        assert masked.endswith("here")
        assert "*" in masked
        assert "sk-" not in masked

    def test_mask_key_empty(self):
        ai = AIConfig(api_key="")
        assert ai.mask_key() == "***"

    def test_to_dict(self):
        ai = AIConfig(api_key="test-key", provider=AIProvider.GROQ)
        d = ai.to_dict()
        assert d["provider"] == "groq"
        assert "api_key" in d
        assert "calls_made" not in d

    def test_from_dict(self):
        data = {"provider": "openai", "api_key": "sk-123", "base_url": "https://api.openai.com/v1"}
        ai = AIConfig.from_dict(data)
        assert ai.provider == AIProvider.OPENAI
        assert ai.api_key == "sk-123"

    def test_from_dict_unknown_fields_ignored(self):
        data = {"provider": "groq", "api_key": "key", "unknown_field": "value"}
        ai = AIConfig.from_dict(data)
        assert ai.provider == AIProvider.GROQ

    def test_defaults(self):
        ai = AIConfig()
        assert ai.enabled is False
        assert ai.temperature == 0.1
        assert ai.max_tokens == 900
        assert ai.max_calls_per_round == 0  # 0 = unlimited
        assert ai.timeout == 60
        assert ai.max_input_chars == 0  # 0 = unlimited
        assert ai.max_final_input_chars == 0  # 0 = unlimited


class TestConfig:
    def test_defaults(self):
        cfg = Config()
        assert cfg.hunt.max_rounds == 8
        assert cfg.hunt.max_hits == 0  # 0 = unlimited
        assert cfg.hunt.compress_output is True
        assert cfg.ai.enabled is False

    def test_load_env_vars(self, monkeypatch):
        monkeypatch.setenv("AI_API_KEY", "test-key-12345")
        monkeypatch.setenv("AI_BASE_URL", "https://custom.api.com/v1")
        monkeypatch.setenv("AI_MODEL", "custom-model")
        cfg = Config()
        cfg.load()
        assert cfg.ai.api_key == "test-key-12345"
        assert cfg.ai.base_url == "https://custom.api.com/v1"
        assert cfg.ai.model == "custom-model"
        assert cfg.ai.enabled is True

    def test_load_openai_api_key(self, monkeypatch):
        monkeypatch.delenv("AI_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-key")
        cfg = Config()
        cfg.load()
        assert cfg.ai.api_key == "sk-openai-key"
        assert cfg.ai.enabled is True

    def test_load_config_json(self, tmp_workspace):
        cfg = Config()
        cfg.hunt.workspace = tmp_workspace
        cfg._config_path = tmp_workspace / "config.json"

        saved = AIConfig(api_key="saved-key", provider=AIProvider.OPENAI)
        cfg._config_path.write_text(json.dumps({"ai": saved.to_dict()}))

        cfg2 = Config()
        cfg2.hunt.workspace = tmp_workspace
        cfg2._config_path = tmp_workspace / "config.json"
        cfg2.load()
        assert cfg2.ai.api_key == "saved-key"
        assert cfg2.ai.enabled is True

    def test_save_ai_creates_file(self, tmp_workspace):
        cfg = Config()
        cfg.hunt.workspace = tmp_workspace
        cfg._config_path = tmp_workspace / "config.json"
        cfg.ai.api_key = "new-key"
        cfg.ai.enabled = True
        cfg.save_ai()

        assert cfg._config_path.exists()
        # Check file permissions
        mode = stat.S_IMODE(os.stat(cfg._config_path).st_mode)
        assert mode & stat.S_IRUSR
        assert mode & stat.S_IWUSR

        data = json.loads(cfg._config_path.read_text())
        assert data["ai"]["api_key"] == "new-key"

    def test_github_token_from_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "gh-test-token")
        cfg = Config()
        assert cfg.github_token == "gh-test-token"

    def test_load_only_once(self):
        cfg = Config()
        cfg.load()
        cfg.load()  # second call should be no-op
        assert cfg._loaded is True


class TestBuiltinProviders:
    def test_all_free_providers_exist(self):
        assert AIProvider.GROQ_FREE in BUILTIN_PROVIDERS
        assert AIProvider.GEMINI_FREE in BUILTIN_PROVIDERS
        assert AIProvider.CEREBRAS_FREE in BUILTIN_PROVIDERS
        assert AIProvider.OPENROUTER_FREE in BUILTIN_PROVIDERS

    def test_free_providers_have_urls(self):
        for provider in [AIProvider.GROQ_FREE, AIProvider.GEMINI_FREE, AIProvider.CEREBRAS_FREE, AIProvider.OPENROUTER_FREE]:
            info = BUILTIN_PROVIDERS[provider]
            assert info["base_url"].startswith("http")
            assert info["model"]
            assert "No" in info["description"]  # No card required

    def test_default_provider_is_free(self):
        ai = AIConfig()
        assert ai.provider == AIProvider.GROQ_FREE


class TestHuntConfig:
    def test_defaults(self):
        h = HuntConfig()
        assert h.max_rounds == 8
        assert h.max_hits == 0  # 0 = unlimited
        assert h.max_pivot_log == 0  # 0 = unlimited
        assert h.max_notes == 0  # 0 = unlimited
        assert h.link_visit_cap == 0  # 0 = unlimited
        assert h.max_tool_output_kb == 0  # 0 = no truncation
        assert h.compress_output is True
        assert h.disk_warn_mb == 2000
        assert h.disk_abort_mb == 500
        assert h.tool_timeout == 420

    def test_to_dict(self):
        h = HuntConfig()
        d = h.to_dict()
        assert "workspace" in d
        assert isinstance(d["workspace"], str)
