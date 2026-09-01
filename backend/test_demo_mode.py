"""Demo-mode guard tests.

Verifies that a hosted build (DEMO_MODE on) still serves the analyzer but blocks
the shared-state-leaking live-mailbox flows, and that a private build does not.

Needs fastapi's TestClient (httpx). If that isn't installed the file skips itself
so `python test_demo_mode.py` never hard-fails in a minimal environment.

Run directly:  python test_demo_mode.py
"""
import importlib
import os
import sys

try:
    from fastapi.testclient import TestClient  # noqa: F401
except Exception:  # pragma: no cover - optional dep
    print("SKIP  fastapi TestClient / httpx not installed — skipping demo-mode API tests")
    raise SystemExit(0)


def _load_app(env):
    """(Re)import app with a controlled environment so module-level flags recompute."""
    for key in ("RENDER", "PORT", "FLY_APP_NAME", "DEMO_MODE", "ALLOW_LIVE_GMAIL",
                "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
        os.environ.pop(key, None)
    os.environ.update(env)
    for mod in ("app", "gmail_oauth_service", "gmail_service"):
        sys.modules.pop(mod, None)
    return importlib.import_module("app")


PHISH_PAYLOAD = {
    "sender_address": "security@paypa1-login.com",
    "display_name": "PayPal",
    "subject": "Your account will be suspended within 24 hours",
    "body": "Verify now: http://paypa1-login.com/verify",
    "spf_status": "FAIL", "dkim_status": "FAIL", "dmarc_status": "FAIL",
}


def test_demo_build_reports_demo_mode():
    app = _load_app({"RENDER": "true"})
    c = TestClient(app.app)
    cfg = c.get("/api/config").json()
    assert cfg["demo_mode"] is True and cfg["allow_live_gmail"] is False, cfg


def test_demo_build_still_analyzes():
    app = _load_app({"RENDER": "true"})
    c = TestClient(app.app)
    r = c.post("/api/analyze", json=PHISH_PAYLOAD)
    assert r.status_code == 200, r.text
    assert r.json()["analysis"]["verdict"] == "PHISHING_ATTACK"


def test_demo_build_blocks_live_gmail():
    app = _load_app({"RENDER": "true"})
    c = TestClient(app.app)
    assert c.get("/api/auth/google/login").status_code == 403
    assert c.post("/api/sentinel/connect-gmail",
                  json={"email": "x@gmail.com", "app_password": "abcdabcdabcdabcd"}).status_code == 403
    # saving just an address (no live connection) is still allowed
    assert c.post("/api/sentinel/connect-gmail", json={"email": "x@gmail.com"}).status_code == 200


def test_private_build_allows_live_gmail():
    app = _load_app({"RENDER": "true", "DEMO_MODE": "0"})
    c = TestClient(app.app)
    cfg = c.get("/api/config").json()
    assert cfg["demo_mode"] is False
    # 400 = "no OAuth client configured" (the pre-existing behaviour), NOT 403
    assert c.get("/api/auth/google/login").status_code == 400


def test_shared_google_client_reenables_live_gmail():
    app = _load_app({"RENDER": "true", "GOOGLE_CLIENT_ID": "x.apps.googleusercontent.com",
                     "GOOGLE_CLIENT_SECRET": "GOCSPX-secret"})
    c = TestClient(app.app)
    cfg = c.get("/api/config").json()
    assert cfg["demo_mode"] is True and cfg["allow_live_gmail"] is True, cfg


def _restore():
    for mod in ("app", "gmail_oauth_service", "gmail_service"):
        sys.modules.pop(mod, None)
    for key in ("RENDER", "DEMO_MODE", "ALLOW_LIVE_GMAIL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
        os.environ.pop(key, None)


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
    _restore()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
