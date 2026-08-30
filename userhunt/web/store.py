"""
Shared event store for the web dashboard.
Thread-safe append-only log that the SSE endpoint reads from.
"""
import time
import json
import threading
from typing import Any, Dict, List, Optional
from collections import deque


class EventStore:
    """
    Central event store for live dashboard updates.
    All scanners, evidence collector, AI engine, and CLI write here.
    The SSE endpoint reads from here and pushes to browsers.
    """

    def __init__(self, max_logs: int = 5000):
        self._lock = threading.Lock()
        self._logs: deque[Dict[str, Any]] = deque(maxlen=max_logs)
        self._tool_output: deque[Dict[str, Any]] = deque(maxlen=max_logs)
        self._hits: List[Dict[str, Any]] = []
        self._pivots: List[Dict[str, Any]] = []
        self._evidence: List[Dict[str, Any]] = []
        self._rounds: List[Dict[str, Any]] = []
        self._status: str = "idle"
        self._current_round: int = 0
        self._total_rounds: int = 8
        self._identifiers: Dict[str, List[str]] = {
            "usernames": [], "emails": [], "names": [],
        }
        self._ai_verdicts: List[Dict[str, Any]] = []
        self._scan_stats: Dict[str, Any] = {}
        self._start_time: Optional[float] = None

    # ── Status ──────────────────────────────────────────────────────

    def set_status(self, status: str) -> None:
        with self._lock:
            self._status = status

    def set_round(self, current: int, total: int = 8) -> None:
        with self._lock:
            self._current_round = current
            self._total_rounds = total
            self._rounds.append({
                "round": current,
                "total": total,
                "time": time.time(),
            })

    def set_identifiers(self, usernames: List[str], emails: List[str], names: List[str]) -> None:
        with self._lock:
            self._identifiers = {
                "usernames": list(usernames),
                "emails": list(emails),
                "names": list(names),
            }

    def start_timer(self) -> None:
        with self._lock:
            self._start_time = time.time()

    # ── Logging ─────────────────────────────────────────────────────

    def log(self, message: str, level: str = "info", source: str = "system") -> None:
        """Add a log entry."""
        entry = {
            "time": time.time(),
            "level": level,
            "source": source,
            "message": message,
        }
        with self._lock:
            self._logs.append(entry)

    def tool_log(self, tool: str, line: str, direction: str = "stdout") -> None:
        """Add a tool output line."""
        entry = {
            "time": time.time(),
            "tool": tool,
            "line": line,
            "direction": direction,
        }
        with self._lock:
            self._tool_output.append(entry)

    def add_hit(self, hit: Dict[str, Any]) -> None:
        """Add a found hit."""
        with self._lock:
            self._hits.append(hit)
            self.log(
                f"HIT: {hit.get('platform', '?')} — {hit.get('url', '?')} [{hit.get('confidence', '?')}]",
                level="hit",
                source=hit.get("scanner", "unknown"),
            )

    def add_hits(self, hits: List[Dict[str, Any]]) -> None:
        """Add multiple hits."""
        for h in hits:
            self.add_hit(h)

    def add_pivot(self, pivot: Dict[str, Any]) -> None:
        """Add a pivot entry."""
        with self._lock:
            self._pivots.append(pivot)

    def add_evidence(self, evidence: Dict[str, Any]) -> None:
        """Add evidence from page visit."""
        with self._lock:
            self._evidence.append(evidence)

    def add_ai_verdict(self, verdict: Dict[str, Any]) -> None:
        """Add AI verdict."""
        with self._lock:
            self._ai_verdicts.append(verdict)
            self.log(
                f"AI: {verdict.get('verdict', '?')} — {verdict.get('target', '?')} ({verdict.get('reason', '')})",
                level="ai",
                source="ai_engine",
            )

    def update_scan_stats(self, stats: Dict[str, Any]) -> None:
        """Update scanner statistics."""
        with self._lock:
            self._scan_stats.update(stats)

    # ── Snapshot (for SSE / API) ────────────────────────────────────

    def snapshot(self, since: float = 0) -> Dict[str, Any]:
        """
        Get a snapshot of all state.
        If since > 0, only return entries newer than that timestamp.
        """
        with self._lock:
            elapsed = time.time() - self._start_time if self._start_time else 0

            logs = list(self._logs) if since == 0 else [
                l for l in self._logs if l["time"] > since
            ]
            tool_output = list(self._tool_output) if since == 0 else [
                t for t in self._tool_output if t["time"] > since
            ]
            hits = self._hits
            pivots = self._pivots if since == 0 else [
                p for p in self._pivots if p.get("time", 0) > since
            ]
            evidence = self._evidence if since == 0 else [
                e for e in self._evidence if e.get("time", 0) > since
            ]
            ai_verdicts = self._ai_verdicts if since == 0 else [
                v for v in self._ai_verdicts if v.get("time", 0) > since
            ]

            return {
                "status": self._status,
                "current_round": self._current_round,
                "total_rounds": self._total_rounds,
                "elapsed_seconds": round(elapsed, 1),
                "identifiers": self._identifiers,
                "logs": logs,
                "tool_output": tool_output,
                "hits": hits,
                "hit_count": len(hits),
                "high_count": sum(1 for h in hits if h.get("confidence") == "HIGH"),
                "medium_count": sum(1 for h in hits if h.get("confidence") == "MEDIUM"),
                "low_count": sum(1 for h in hits if h.get("confidence") == "LOW"),
                "pivots": pivots[-100:],
                "evidence": evidence[-50:],
                "ai_verdicts": ai_verdicts[-50:],
                "scan_stats": self._scan_stats,
                "timestamp": time.time(),
            }

    def reset(self) -> None:
        """Clear all state for a new hunt."""
        with self._lock:
            self._logs.clear()
            self._tool_output.clear()
            self._hits.clear()
            self._pivots.clear()
            self._evidence.clear()
            self._rounds.clear()
            self._ai_verdicts.clear()
            self._scan_stats.clear()
            self._status = "idle"
            self._current_round = 0
            self._start_time = None


# Singleton instance
store = EventStore()
