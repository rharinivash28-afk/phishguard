"""Per-session isolation tests.

Verifies that each browser session is a private workspace: data created by one
session is invisible to another and to an anonymous (no-cookie) caller, wipe only
affects the caller, and the Gmail app password is stored encrypted.

Needs fastapi's TestClient (httpx). Self-skips if that isn't installed so
`python test_sessions.py` never hard-fails in a minimal environment.

Run directly:  python test_sessions.py
"""
import os
import sys
import tempfile

# use a throwaway SQLite file so a dev DB is never touched
_TMP_DB = os.path.join(tempfile.gettempdir(), "phishguard_test_sessions.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ.pop("RENDER", None)
os.environ.pop("PORT", None)

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover - optional dep
    print("SKIP  fastapi TestClient / httpx not installed — skipping session tests")
    raise SystemExit(0)

if os.path.exists(_TMP_DB):
    os.remove(_TMP_DB)

import app  # noqa: E402
from db import GmailAccount, InboxItem, SessionLocal, init_db  # noqa: E402

init_db()

PHISH = {
    "sender_address": "security@paypa1-login.com",
    "display_name": "PayPal",
    "subject": "Your account will be suspended within 24 hours",
    "body": "Verify now: http://paypa1-login.com/verify",
    "spf_status": "FAIL", "dkim_status": "FAIL", "dmarc_status": "FAIL",
}


def _client():
    c = TestClient(app.app)
    c.get("/api/session")  # mint cookie
    return c


def test_fresh_workspace_inbox_is_empty():
    """No demo seed — a brand-new session starts with an empty inbox."""
    c = _client()
    inbox = c.get("/api/sentinel/inbox").json()["inbox"]
    assert inbox == [], f"expected empty inbox, got {len(inbox)} items"
    stats = c.get("/api/sentinel/stats").json()
    assert stats["total_emails_scanned"] == 0
    assert stats["monitoring_mode"] == "AWAITING_CONNECTION"


def test_samples_endpoint_returns_three_presets():
    c = _client()
    data = c.get("/api/samples").json()
    assert len(data["presets"]) == 3
    titles = {p["title"] for p in data["presets"]}
    assert titles == {"PayPal Phish", "DocuSign Spoof", "Legitimate Google Alert"}


def test_two_sessions_are_isolated():
    a, b = _client(), _client()
    a.post("/api/sentinel/simulate-incoming")
    a.post("/api/sentinel/simulate-incoming")
    a_sims = [x for x in a.get("/api/sentinel/inbox").json()["inbox"] if x["id"].startswith("live_sim_")]
    b_sims = [x for x in b.get("/api/sentinel/inbox").json()["inbox"] if x["id"].startswith("live_sim_")]
    assert len(a_sims) == 2, a_sims
    assert len(b_sims) == 0, "session B can see session A's injected mail"


def test_incident_report_reachable_after_simulate():
    """The Report button 404 bug: a quarantined email's incident_id must resolve
    to a dossier in the SAME session, even when another session already
    quarantined the identical sample."""
    a, b = _client(), _client()
    # both quarantine the same PayPal sample
    ia = a.post("/api/sentinel/simulate-incoming").json()["item"]
    ib = b.post("/api/sentinel/simulate-incoming").json()["item"]
    assert ia["incident_id"] and ib["incident_id"]
    assert ia["incident_id"] != ib["incident_id"], "incident ids collide across sessions"
    # each session can fetch its own dossier
    ra = a.get(f"/api/sentinel/report/{ia['incident_id']}")
    rb = b.get(f"/api/sentinel/report/{ib['incident_id']}")
    assert ra.status_code == 200, f"session A got {ra.status_code} for its own report"
    assert rb.status_code == 200, f"session B got {rb.status_code} for its own report"
    assert ra.json()["report"]["stix_bundle"]["type"] == "bundle"
    # and each session's reports list has exactly one
    assert len(a.get("/api/sentinel/reports").json()["reports"]) == 1
    assert len(b.get("/api/sentinel/reports").json()["reports"]) == 1
    # cross access is denied
    assert a.get(f"/api/sentinel/report/{ib['incident_id']}").status_code == 404


def test_generate_report_endpoint_persists_to_reports_tab():
    c = _client()
    c.post("/api/generate-report", json={
        "sender_address": "security@paypa1-verify.xyz", "display_name": "PayPal",
        "subject": "Urgent: verify within 24 hours", "body": "http://paypa1-verify.xyz/login",
        "spf_status": "FAIL", "dkim_status": "FAIL", "dmarc_status": "FAIL",
    })
    reports = c.get("/api/sentinel/reports").json()["reports"]
    assert len(reports) == 1, "Deep Forensics report did not land in the Reports tab"
    assert reports[0]["stix_bundle"]


def test_anonymous_caller_gets_fresh_workspace():
    a = _client()
    a.post("/api/sentinel/simulate-incoming")
    anon = TestClient(app.app)  # never calls /api/session, no cookie sent
    inbox = anon.get("/api/sentinel/inbox").json()["inbox"]
    assert inbox == [], "anon caller saw another session's data"


def test_wipe_only_affects_caller():
    a, b = _client(), _client()
    b.post("/api/sentinel/simulate-incoming")
    a.post("/api/session/wipe")
    b_sims = [x for x in b.get("/api/sentinel/inbox").json()["inbox"] if x["id"].startswith("live_sim_")]
    assert len(b_sims) == 1, "wiping session A also wiped session B"


def test_analyze_scoped_and_correct():
    c = _client()
    r = c.post("/api/analyze", json=PHISH)
    assert r.status_code == 200, r.text
    assert r.json()["analysis"]["verdict"] == "PHISHING_ATTACK"


def test_app_password_is_encrypted_at_rest():
    from crypto import decrypt, encrypt
    secret = "abcdabcdabcdabcd"
    token = encrypt(secret)
    assert token != secret and decrypt(token) == secret
    # and nothing in the table stores the plaintext
    db = SessionLocal()
    try:
        for acct in db.query(GmailAccount).all():
            assert secret not in (acct.app_password_enc or "")
    finally:
        db.close()


def test_config_reports_app_password_method():
    c = _client()
    cfg = c.get("/api/config").json()
    assert cfg["gmail_method"] == "app_password"
    assert "version" in cfg


def test_no_google_oauth_routes():
    paths = {getattr(r, "path", "") for r in app.app.routes}
    assert not any(p.startswith("/api/auth/google") for p in paths), "stale Google OAuth routes present"


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
