"""Connection stability + duration tests.

- transient network errors must NOT drop a valid connection
- a run of transient failures eventually does
- an auth rejection drops it on the first hit
- connection duration expiry tears the connection down (poll + poller)
- Permanent (duration_hours=None) never expires

Forces a throwaway SQLite DB; self-skips without fastapi TestClient.
Run: python test_connection.py
"""
import datetime
import os
import sys
import tempfile

_TMP_DB = os.path.join(tempfile.gettempdir(), "phishguard_test_connection.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ.pop("RENDER", None)
os.environ.pop("PORT", None)
os.environ["RATE_LIMIT_ENABLED"] = "0"

try:
    from fastapi.testclient import TestClient  # noqa: F401
except Exception:  # pragma: no cover
    print("SKIP  fastapi TestClient / httpx not installed — skipping connection tests")
    raise SystemExit(0)

if os.path.exists(_TMP_DB):
    os.remove(_TMP_DB)

import app  # noqa: E402
import gmail_service  # noqa: E402
from db import GmailAccount, SessionLocal, init_db  # noqa: E402
from gmail_service import GmailAuthError, GmailTransientError  # noqa: E402
from user_workspace import UserWorkspace  # noqa: E402

init_db()


def _make_connected_account(session_id="sess-conn", duration_hours=24, connected_at=None):
    db = SessionLocal()
    from db import Session as Sess

    if db.get(Sess, session_id) is None:
        db.add(Sess(id=session_id))
        db.commit()
    acct = db.get(GmailAccount, session_id)
    if acct is None:
        acct = GmailAccount(session_id=session_id, email="u@gmail.com",
                            app_password_enc="x", seen_ids=[])
        db.add(acct)
    acct.connected = True
    acct.consecutive_failures = 0
    acct.duration_hours = duration_hours
    acct.connected_at = connected_at or datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.close()
    return session_id


def _patch_fetch(exc):
    def _raise(*a, **k):
        raise exc
    gmail_service.fetch_new_messages = _raise
    import user_workspace
    user_workspace.fetch_new_messages = _raise


def _restore_fetch():
    import importlib
    importlib.reload(gmail_service)
    import user_workspace
    user_workspace.fetch_new_messages = gmail_service.fetch_new_messages


def test_transient_error_keeps_connection():
    sid = _make_connected_account("sess-transient")
    _patch_fetch(GmailTransientError("network blip"))
    try:
        db = SessionLocal()
        for _ in range(4):
            res = UserWorkspace(sid, db).poll_live_gmail()
            assert res["status"] == "TRANSIENT", res
        acct = db.get(GmailAccount, sid)
        assert acct.connected is True, "connection dropped on transient errors"
        assert acct.consecutive_failures == 4
        db.close()
    finally:
        _restore_fetch()


def test_transient_run_eventually_disconnects():
    sid = _make_connected_account("sess-run")
    _patch_fetch(GmailTransientError("still down"))
    try:
        db = SessionLocal()
        statuses = [UserWorkspace(sid, db).poll_live_gmail()["status"] for _ in range(6)]
        acct = db.get(GmailAccount, sid)
        assert acct.connected is False, "5 straight failures should disconnect"
        assert "AUTH_FAILED" in statuses
        db.close()
    finally:
        _restore_fetch()


def test_auth_error_disconnects_immediately():
    sid = _make_connected_account("sess-auth")
    _patch_fetch(GmailAuthError("Invalid credentials"))
    try:
        db = SessionLocal()
        res = UserWorkspace(sid, db).poll_live_gmail()
        assert res["status"] == "AUTH_FAILED"
        assert db.get(GmailAccount, sid).connected is False
        db.close()
    finally:
        _restore_fetch()


def test_duration_expiry_tears_down():
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    sid = _make_connected_account("sess-expire", duration_hours=1, connected_at=past)
    db = SessionLocal()
    ws = UserWorkspace(sid, db)
    res = ws.poll_live_gmail()
    assert res["status"] == "EXPIRED", res
    assert db.get(GmailAccount, sid) is None, "expired account row not deleted"
    assert ws.list_inbox() == [], "inbox not cleared on expiry"
    db.close()


def test_permanent_never_expires():
    long_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
    sid = _make_connected_account("sess-perm", duration_hours=None, connected_at=long_ago)
    db = SessionLocal()
    ws = UserWorkspace(sid, db)
    status = ws.connection_status()
    assert status["connected"] is True
    assert status["permanent"] is True
    assert status["expires_at"] is None
    assert ws._enforce_duration() is False
    db.close()


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
