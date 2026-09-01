"""Second-opinion phishing classifier via an NVIDIA-hosted LLM.

OpenAI-compatible endpoint at build.nvidia.com. Off unless NVIDIA_API_KEY is set.
Only called for borderline heuristic scores (see caller) to stay well under the
free rate limit. Never allowed to *lower* a verdict — it can only add concern.
"""
import json
import os
from typing import Any, Dict, Optional

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None

_BASE_URL = "https://integrate.api.nvidia.com/v1"
_DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"

_SYSTEM = (
    "You are a phishing-detection analyst. Given an email's fields, decide how likely "
    "it is a phishing / social-engineering / scam attempt. Reply with ONLY a compact "
    "JSON object, no prose, no markdown fences:\n"
    '{"risk": <int 0-100>, "rationale": "<one sentence>", '
    '"red_flags": ["<short phrase>", ...]}\n'
    "risk 0-20 = clearly legitimate, 21-49 = mildly suspicious, 50-79 = likely "
    "phishing, 80-100 = almost certainly phishing. Keep red_flags to at most 4 items."
)


def _client() -> Optional["OpenAI"]:
    key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not key or OpenAI is None:
        return None
    return OpenAI(base_url=_BASE_URL, api_key=key, timeout=8.0, max_retries=0)


def is_enabled() -> bool:
    return bool(os.environ.get("NVIDIA_API_KEY", "").strip()) and OpenAI is not None


def llm_verdict(email_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return {risk:int, rationale:str, red_flags:[str]} or None on any problem."""
    client = _client()
    if client is None:
        return None

    urls = email_data.get("urls") or []
    url_lines = "\n".join(
        f"  - {u.get('url','')}" + (f"  (link text: {u.get('anchor')})" if u.get("anchor") else "")
        for u in urls[:15]
    )
    atts = ", ".join(a.get("filename", "") for a in (email_data.get("attachments") or [])[:10])
    body = (email_data.get("body") or "")[:4000]

    user = (
        f"From name: {email_data.get('display_name','')}\n"
        f"From address: {email_data.get('sender_address','')}\n"
        f"Subject: {email_data.get('subject','')}\n"
        f"SPF/DKIM/DMARC: {email_data.get('spf_status','?')}/"
        f"{email_data.get('dkim_status','?')}/{email_data.get('dmarc_status','?')}\n"
        f"Attachments: {atts or 'none'}\n"
        f"Links:\n{url_lines or '  none'}\n\n"
        f"Body:\n{body}"
    )

    try:
        resp = client.chat.completions.create(
            model=os.environ.get("NVIDIA_MODEL", _DEFAULT_MODEL),
            messages=[{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}],
            temperature=0.1,
            max_tokens=300,
        )
        raw = (resp.choices[0].message.content or "").strip()
        if raw.startswith("```"):
            raw = raw.strip("`").lstrip("json").strip()
        data = json.loads(raw)
        risk = int(max(0, min(100, data.get("risk", 0))))
        flags = [str(f)[:120] for f in (data.get("red_flags") or [])][:4]
        return {"risk": risk, "rationale": str(data.get("rationale", ""))[:400], "red_flags": flags}
    except Exception:
        return None
