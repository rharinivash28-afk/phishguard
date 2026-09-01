"""Google Safe Browsing URL reputation lookup.

Off unless GOOGLE_SAFE_BROWSING_KEY is set. Results are cached in-process for an
hour so repeated scans of the same links are free.
"""
import os
import time
from typing import Dict, List

import requests

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_CACHE: Dict[str, tuple[float, str]] = {}
_TTL = 3600.0
_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def _key() -> str:
    return os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "").strip()


def check_urls(urls: List[str]) -> Dict[str, str]:
    """Return {url: threat_type} for any URL Google flags. Empty dict if the key
    is unset, the call fails, or nothing matches."""
    key = _key()
    urls = [u for u in dict.fromkeys(urls) if u]
    if not key or not urls:
        return {}

    now = time.time()
    hits: Dict[str, str] = {}
    to_query: List[str] = []
    for u in urls:
        cached = _CACHE.get(u)
        if cached and now - cached[0] < _TTL:
            if cached[1]:
                hits[u] = cached[1]
        else:
            to_query.append(u)

    if to_query:
        body = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": _THREATS,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in to_query[:500]],
            },
        }
        try:
            r = requests.post(f"{_ENDPOINT}?key={key}", json=body, timeout=3)
            matched = {}
            if r.status_code == 200:
                for m in r.json().get("matches", []):
                    u = m.get("threat", {}).get("url", "")
                    if u:
                        matched[u] = m.get("threatType", "UNSAFE")
            for u in to_query:
                _CACHE[u] = (now, matched.get(u, ""))
                if u in matched:
                    hits[u] = matched[u]
        except Exception:
            pass  # network hiccup — treat as no data

    return hits
