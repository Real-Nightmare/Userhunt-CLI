"""
Storage management — disk checks, output truncation, ring buffers.
Enforces 5GB disk constraint.
"""
import os
import shutil
from collections import deque
from pathlib import Path
from typing import Any, Deque, List


def check_disk(workspace: Path, warn_mb: int = 2000, abort_mb: int = 500) -> bool:
    """Check free disk space. Returns False if below abort threshold."""
    try:
        usage = shutil.disk_usage(str(workspace))
        free_mb = usage.free / (1024 * 1024)
        if free_mb < abort_mb:
            print(
                f"\033[1;31mABORT: Only {free_mb:.0f}MB free. "
                f"Minimum {abort_mb}MB required.\033[0m"
            )
            return False
        if free_mb < warn_mb:
            print(
                f"\033[1;33mWARN: Only {free_mb:.0f}MB free disk space.\033[0m"
            )
    except Exception:
        pass
    return True


def free_disk_mb(workspace: Path) -> float:
    """Return free disk space in MB, or -1 on error."""
    try:
        usage = shutil.disk_usage(str(workspace))
        return usage.free / (1024 * 1024)
    except Exception:
        return -1.0


def truncate_output(text: str, max_kb: int = 0) -> str:
    """Truncate tool output to max_kb kilobytes. 0 = no truncation (full accuracy)."""
    if max_kb <= 0:
        return text
    max_chars = max_kb * 1024
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n...[truncated at {max_kb}KB]"


def purge_temp_files(workspace: Path, tool_names: tuple = ("maigret", "nexfil", "photon")) -> None:
    """Delete temporary output directories for specified tools."""
    data_dir = workspace / "data"
    if not data_dir.exists():
        return
    for name in tool_names:
        for d in data_dir.glob(f"{name}_*"):
            if d.is_dir():
                try:
                    shutil.rmtree(d)
                except Exception:
                    pass


class RingBuffer:
    """Fixed-capacity ring buffer backed by a deque."""

    def __init__(self, maxlen: int):
        self._buf: Deque[Any] = deque(maxlen=maxlen)
        self._maxlen = maxlen

    @property
    def maxlen(self) -> int:
        return self._maxlen

    def append(self, item: Any) -> None:
        self._buf.append(item)

    def extend(self, items: List[Any]) -> None:
        self._buf.extend(items)

    def clear(self) -> None:
        self._buf.clear()

    def __len__(self) -> int:
        return len(self._buf)

    def __iter__(self):
        return iter(self._buf)

    def __bool__(self) -> bool:
        return bool(self._buf)

    def as_list(self) -> List[Any]:
        return list(self._buf)

    def last(self, n: int = 50) -> List[Any]:
        return list(self._buf)[-n:]
