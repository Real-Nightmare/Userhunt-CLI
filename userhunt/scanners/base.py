"""
Base scanner class for all OSINT scanners.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from userhunt.config import Config


class BaseScanner(ABC):
    def __init__(self, config: Config):
        self.config = config
        self.name = "base"
        self.status = "CORE"

    def scan(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Default scan — subclasses override scan_usernames/scan_emails/etc."""
        return []

    def _make_hit(self, platform: str, url: str, confidence: str = "MEDIUM", **kwargs) -> Dict[str, Any]:
        return {
            "platform": platform,
            "url": url,
            "confidence": confidence,
            "scanner": self.name,
            "status": "found",
            **kwargs,
        }
