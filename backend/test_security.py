"""Security-hardening tests: rate limits, headers, size caps, cron guard.

Forces a throwaway SQLite DB and self-skips without fastapi TestClient / httpx.
Run directly:  python test_security.py
"""
import os
import tempfile

_TMP_DB = os.path.join(tempfile.gettempdir(), "phishguard_test_security.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["CRON_SECRET"] = "unit-test-cron-secret"
os.environ.pop("RENDER", None)
os.environ.pop("PORT", None)

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    print("SKIP  fastapi TestClient / httpx not installed — skipping security tests")
    raise SystemExit(0)

if os.path.exists(_TMP_DB):
    os.remove(_TMP_DB)

PHISH = {"sender_address": "a@b.com", "subject": "x", "body": "y"}


def _fresh_app(rate_limit: bool):
    """Import app with a controlled RATE_LIMIT_ENABLED so tests don't interfere."""
    import importlib
    import sys

    os.environ["RATE_LIMIT_ENABLED"] = "1" if rate_limit else "0"
    for m in ("app", "poller", "session_store"):
        sys.modules.pop(m, None)
    mod = importlib.import_module("app")
    from db import init_db

    init_db()
    return mod


# most tests: rate limiting OFF so they don't exhaust each other's budget
_APP = _fresh_app(rate_limit=False)


def _client(app_mod=None):
    c = TestClient((app_mod or _APP).app)
    c.get("/api/session")
    return c


def test_security_headers_present():
    r = _client().get("/api/health")
    h = r.headers
    assert h.get("x-content-type-options") == "nosniff"
    assert h.get("x-frame-options") == "DENY"
    assert "content-security-policy" in h
    assert "frame-ancestors 'none'" in h["content-security-policy"]


def test_analyze_rate_limited():
    rl_app = _fresh_app(rate_limit=True)
    c = _client(rl_app)
    codes = [c.post("/api/analyze", json=PHISH).status_code for _ in range(40)]
    assert 429 in codes, "rate limiter never triggered"
    assert codes.count(200) <= 31, f"too many requests allowed: {codes.count(200)}"
    # restore the shared no-rate-limit app for the remaining tests
    global _APP
    _APP = _fresh_app(rate_limit=False)


def test_cron_requires_secret():
    c = TestClient(_APP.app)
    assert c.post("/api/cron/poll-tick").status_code == 403
    assert c.post("/api/cron/poll-tick", headers={"X-Cron-Key": "wrong"}).status_code == 403
    ok = c.post("/api/cron/poll-tick", headers={"X-Cron-Key": "unit-test-cron-secret"})
    assert ok.status_code == 200 and "scanned_sessions" in ok.json()


def test_body_is_capped():
    c = _client()
    huge = "A" * 60_000
    c.post("/api/analyze", json={"sender_address": "a@b.com", "subject": "s", "body": huge})
    inbox = c.get("/api/sentinel/inbox").json()["inbox"]
    stored = next(i for i in inbox if i["subject"] == "s")
    assert len(stored["body"]) <= 20_050, f"body not truncated: {len(stored['body'])}"


def test_url_list_is_capped():
    c = _client()
    urls = [{"url": f"http://ex{i}.com/a", "anchor": ""} for i in range(120)]
    c.post("/api/analyze", json={"sender_address": "a@b.com", "subject": "many", "body": "b", "urls": urls})
    inbox = c.get("/api/sentinel/inbox").json()["inbox"]
    stored = next(i for i in inbox if i["subject"] == "many")
    assert len(stored["urls"]) <= 50


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}\n      {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
