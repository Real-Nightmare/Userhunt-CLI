"""
Centralized regex extractors for OSINT identifiers.
Used by pivot engine, evidence collector, and scanners.
"""
import re
from typing import Dict, List, Set


# ── Compiled patterns ──────────────────────────────────────────────

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
URL_RE = re.compile(r'https?://[^\s<>"\')]+')
HANDLE_RE = re.compile(r'@([a-zA-Z0-9_]{3,30})')
USERNAME_PATH_RE = re.compile(r'/(?:u|user|profile|members?)/([a-zA-Z0-9._-]{2,40})')
DISCORD_INVITE_RE = re.compile(r'discord\.gg/([A-Za-z0-9_-]+)')
DISCORD_SNOWFLAKE_RE = re.compile(r'\b(\d{17,20})\b')
ROBLOX_ID_RE = re.compile(r'\b(\d{3,16})\b')
BTC_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
PHONE_RE = re.compile(r'\+?\d[\d\s\-()]{7,15}\d')
DOMAIN_RE = re.compile(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)\b')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Clue routing patterns (used by CLI menu option 4)
CLUE_PATTERNS = {
    "email": EMAIL_RE,
    "url": URL_RE,
    "discord_invite": DISCORD_INVITE_RE,
}


def extract_emails(text: str) -> List[str]:
    """Extract all email addresses from text, deduplicated, order-preserving."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in EMAIL_RE.finditer(text):
        val = m.group(0).lower()
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in URL_RE.finditer(text):
        val = m.group(0)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_handles(text: str) -> List[str]:
    """Extract @handles from text."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in HANDLE_RE.finditer(text):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_usernames_from_paths(text: str) -> List[str]:
    """Extract usernames from URL path patterns like /user/foo."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in USERNAME_PATH_RE.finditer(text):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_discord_invites(text: str) -> List[str]:
    """Extract Discord invite codes."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in DISCORD_INVITE_RE.finditer(text):
        val = m.group(0)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_discord_snowflakes(text: str) -> List[str]:
    """Extract Discord snowflake IDs (17-20 digits)."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in DISCORD_SNOWFLAKE_RE.finditer(text):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_roblox_ids(text: str) -> List[str]:
    """Extract Roblox user IDs (3-16 digits)."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in ROBLOX_ID_RE.finditer(text):
        val = m.group(1)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_btc_addresses(text: str) -> List[str]:
    """Extract Bitcoin addresses."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in BTC_RE.finditer(text):
        val = m.group(0)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_phones(text: str) -> List[str]:
    """Extract phone numbers."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in PHONE_RE.finditer(text):
        val = m.group(0).strip()
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_domains(text: str) -> List[str]:
    """Extract domain names (requires at least one dot)."""
    seen: Set[str] = set()
    result: List[str] = []
    for m in DOMAIN_RE.finditer(text):
        val = m.group(1)
        if "." in val and len(val) > 4 and val not in seen:
            seen.add(val)
            result.append(val)
    return result


def extract_identifiers(text: str, source: str = "") -> List[Dict[str, str]]:
    """
    Master extractor — find ALL identifier types in text.
    Returns list of {"type": ..., "value": ..., "source": ...}.
    """
    results: List[Dict[str, str]] = []

    for val in extract_emails(text):
        results.append({"type": "email", "value": val, "source": source})
    for val in extract_urls(text):
        results.append({"type": "url", "value": val, "source": source})
    for val in extract_handles(text):
        results.append({"type": "username", "value": val, "source": source})
    for val in extract_discord_invites(text):
        results.append({"type": "discord_invite", "value": val, "source": source})
    for val in extract_discord_snowflakes(text):
        results.append({"type": "discord_snowflake", "value": val, "source": source})
    for val in extract_roblox_ids(text):
        results.append({"type": "roblox_id", "value": val, "source": source})
    for val in extract_btc_addresses(text):
        results.append({"type": "btc", "value": val, "source": source})
    for val in extract_phones(text):
        results.append({"type": "phone", "value": val, "source": source})
    for val in extract_domains(text):
        results.append({"type": "domain", "value": val, "source": source})
    for val in extract_usernames_from_paths(text):
        results.append({"type": "username", "value": val, "source": source})

    return results


def route_clues(clues: List[str]) -> Dict[str, List[str]]:
    """
    Route raw clue strings to the correct category via regex.
    Multi-word strings → names, single tokens → usernames.
    """
    result: Dict[str, List[str]] = {
        "emails": [], "urls": [], "discord_invites": [], "discord_snowflakes": [],
        "roblox_ids": [], "btc": [], "phones": [], "domains": [], "names": [],
        "usernames": [],
    }
    for clue in clues:
        clue = clue.strip()
        if not clue:
            continue
        if EMAIL_RE.match(clue):
            result["emails"].append(clue)
        elif URL_RE.match(clue):
            result["urls"].append(clue)
        elif DISCORD_INVITE_RE.search(clue):
            result["discord_invites"].append(clue)
        elif DISCORD_SNOWFLAKE_RE.search(clue):
            result["discord_snowflakes"].append(DISCORD_SNOWFLAKE_RE.search(clue).group(1))
        elif BTC_RE.search(clue):
            result["btc"].append(BTC_RE.search(clue).group(0))
        elif re.match(r'^\d+$', clue):
            # Pure digits → roblox/snowflake, not phone
            if len(clue) >= 17:
                result["discord_snowflakes"].append(clue)
            elif len(clue) >= 3:
                result["roblox_ids"].append(clue)
        elif PHONE_RE.search(clue):
            result["phones"].append(clue)
        elif "." in clue and DOMAIN_RE.search(clue) and len(clue) > 4:
            result["domains"].append(DOMAIN_RE.search(clue).group(1))
        elif " " in clue and re.search(r'[a-zA-Z]{3,}', clue):
            result["names"].append(clue)
        elif re.search(r'^[a-zA-Z0-9._-]{2,40}$', clue):
            result["usernames"].append(clue)
        else:
            result["usernames"].append(clue)
    return result
