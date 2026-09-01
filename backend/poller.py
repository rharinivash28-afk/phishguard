"""Background Gmail polling for every connected user.

Two triggers:
- an in-process daemon thread (fires whenever the dyno is awake), and
- `POST /api/cron/poll-tick` (external cron; also wakes a sleeping free dyno).

Both call `run_tick()`. One thread iterating all sessions scales fine for a
free-tier-sized user base; move to a work queue if it ever needs to.
"""
import datetime
import os
import threading
import time

from sqlalchemy import select

from db import GmailAccount, InboxItem, SessionLocal
from session_store import active_session_ids, sweep_expired
from user_workspace import UserWorkspace

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "60"))
INBOX_RETENTION_DAYS = int(os.environ.get("INBOX_RETENTION_DAYS", "30"))
_RETAIN_MIN_PER_SESSION = 200

_started = False
_lock = threading.Lock()


def _prune_old_inbox(db) -> None:
    """Delete inbox rows older than the retention window, keeping the newest N
    per session so an active user's recent history is always intact."""
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=INBOX_RETENTION_DAYS)
    old = db.execute(
        select(InboxItem).where(InboxItem.created_at < cutoff).order_by(InboxItem.created_at.desc())
    ).scalars().all()
    keep_count: dict[str, int] = {}
    for item in old:
        n = keep_count.get(item.session_id, 0)
        if n < _RETAIN_MIN_PER_SESSION:
            keep_count[item.session_id] = n + 1
            continue
        db.delete(item)
    db.commit()


def run_tick(time_budget_s: float = 25.0) -> dict:
    """One polling pass. Bounded by `time_budget_s` (external cron has a 30s cap).
    Processes sessions with the stalest `last_scan_at` first."""
    start = time.monotonic()
    db = SessionLocal()
    scanned = 0
    new_emails = 0
    try:
        ids = active_session_ids(db)
        # order by stalest gmail scan first
        accts = db.execute(
            select(GmailAccount)
            .where(GmailAccount.session_id.in_(ids), GmailAccount.connected.is_(True))
            .order_by(GmailAccount.last_scan_at.is_(None).desc(), GmailAccount.last_scan_at.asc())
        ).scalars().all() if ids else []

        expired = 0
        for acct in accts:
            ws = UserWorkspace(acct.session_id, db)
            # duration expiry is enforced for every connected account each pass,
            # even when the time budget stops us from actually polling it
            if ws._enforce_duration():
                expired += 1
                continue
            if time.monotonic() - start > time_budget_s:
                continue
            try:
                res = ws.poll_live_gmail()
                scanned += 1
                new_emails += int(res.get("new_emails_found", 0) or 0)
            except Exception as exc:  # never let one user's failure kill the pass
                print(f"[poller] session {acct.session_id[:8]}… error: {exc}")

        sweep_expired(db)
        _prune_old_inbox(db)
    finally:
        db.close()
    return {
        "scanned_sessions": scanned,
        "new_emails": new_emails,
        "expired_connections": expired,
        "duration_ms": int((time.monotonic() - start) * 1000),
    }


def _loop() -> None:
    while True:
        try:
            run_tick(time_budget_s=float(POLL_INTERVAL))
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
