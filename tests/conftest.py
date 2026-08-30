"""
Shared test fixtures for Userhunt CLI tests.
"""
import json
import tempfile
from pathlib import Path
from typing import Generator

import pytest

from userhunt.config import Config, AIConfig, HuntConfig


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Create a temporary workspace directory."""
    ws = tmp_path / "userhunt_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "tools").mkdir(exist_ok=True)
    (ws / "output").mkdir(exist_ok=True)
    (ws / "data").mkdir(exist_ok=True)
    return ws


@pytest.fixture
def config(tmp_workspace: Path) -> Config:
    """Create a Config with a temporary workspace."""
    cfg = Config()
    cfg.hunt.workspace = tmp_workspace
    cfg._config_path = tmp_workspace / "config.json"
    return cfg


@pytest.fixture
def case(config: Config):
    """Create a Case with the test config's limits."""
    from userhunt.case import Case
    return Case(
        max_hits=config.hunt.max_hits,
        max_pivot_log=config.hunt.max_pivot_log,
        max_notes=config.hunt.max_notes,
    )
