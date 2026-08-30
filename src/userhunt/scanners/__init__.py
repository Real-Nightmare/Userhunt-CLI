"""
Scanner package for USERHUNT CLI.
"""
from userhunt.scanners.base import BaseScanner
from userhunt.scanners.manager import ScanManager

__all__ = ["BaseScanner", "ScanManager"]
