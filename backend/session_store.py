"""Cookie-based session identity — no login, the opaque cookie IS the identity.

Every visitor gets a `pg_session` cookie on first request. That cookie value is a
row id in the `sessions` table; all of a user's data hangs off it. Sessions expire
after SESSION_TTL_DAYS of inactivity and are swept lazily.
"""
import datetime
import os

from fastapi import Depends, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from db import Session, SessionLocal

COOKIE_NAME = "pg_session"
TTL_DAYS = int(os.environ.get("SESSION_TTL_DAYS", "14"))
_IS_PROD = bool(os.environ.get("RENDER") or os.environ.get("PORT") or os.environ.get("FLY_APP_NAME"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _set_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        max_age=TTL_DAYS * 24 * 3600,
        httponly=True,
        secure=_IS_PROD,          # localhost is http, so only force Secure in prod
        samesite="lax",
        path="/",
    )


def _load_valid(db: OrmSession, session_id: str) -> Session | None:
    if not session_id:
        return None
    row = db.get(Session, session_id)
    if row is None:
        return None
    last_seen = row.last_seen_at
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=datetime.timezone.utc)
    if last_seen and (_now() - last_seen) > datetime.timedelta(days=TTL_DAYS):
        db.delete(row)  # expired — cascade wipes its data
        db.commit()
        return None
    return row


def get_or_create_session(request: Request, response: Response, db: OrmSession) -> Session:
    """Return the caller's Session row, minting one (and the cookie) if needed."""
    row = _load_valid(db, request.cookies.get(COOKIE_NAME, ""))
    if row is None:
        row = Session()
        db.add(row)
        db.commit()
        db.refresh(row)
    else:
        row.last_seen_at = _now()
        db.commit()
    _set_cookie(response, row.id)
    return row


def require_session(request: Request, response: Response, db: OrmSession = Depends(get_db)) -> Session:
    """FastAPI dependency: every data route depends on this."""
    return get_or_create_session(request, response, db)


def sweep_expired(db: OrmSession) -> int:
    cutoff = _now() - datetime.timedelta(days=TTL_DAYS)
    result = db.execute(delete(Session).where(Session.last_seen_at < cutoff))
    db.commit()
    return result.rowcount or 0


def active_session_ids(db: OrmSession) -> list[str]:
    """Sessions the background poller should scan (monitoring on, not expired)."""
    cutoff = _now() - datetime.timedelta(days=TTL_DAYS)
    rows = db.execute(
        select(Session.id).where(
            Session.monitoring_active.is_(True),
            Session.last_seen_at >= cutoff,
        )
    ).scalars().all()
    return list(rows)
