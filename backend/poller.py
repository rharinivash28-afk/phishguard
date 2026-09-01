"""Single background thread that polls every connected user's Gmail.

On Render's free tier the web service sleeps after ~15 min idle, which pauses this
loop too — a documented limitation. A paid always-on instance (or an external cron
hitting an endpoint) removes that. One thread iterating all sessions scales fine
for a free-tier-sized user base; move to a work queue if it ever needs to.
"""
import os
import threading
import time

from db import GmailAccount, SessionLocal
from session_store import active_session_ids, sweep_expired
from user_workspace import UserWorkspace

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "60"))
_started = False
_lock = threading.Lock()


def _tick() -> None:
    db = SessionLocal()
    try:
        session_ids = active_session_ids(db)
        for sid in session_ids:
            acct = db.get(GmailAccount, sid)
            if acct is None or not acct.connected:
                continue
            try:
                UserWorkspace(sid, db).poll_live_gmail()
            except Exception as exc:  # never let one user's failure kill the loop
                print(f"[poller] session {sid[:8]}… error: {exc}")
        sweep_expired(db)
    finally:
        db.close()


def _loop() -> None:
    while True:
        try:
            _tick()
        except Exception as exc:
            print(f"[poller] tick error: {exc}")
        time.sleep(POLL_INTERVAL)


def start_poller() -> None:
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_loop, name="phishguard-poller", daemon=True).start()
