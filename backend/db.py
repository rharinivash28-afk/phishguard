"""Database layer — SQLAlchemy 2.x models and session factory.

In production `DATABASE_URL` points at a Postgres instance (Neon / Supabase free
tier). With no `DATABASE_URL` set we fall back to a local SQLite file so the app
runs with zero external services in dev and tests.
"""
import datetime
import os
import uuid
from typing import Optional

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, String, Text, create_engine, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def _database_url() -> str:
    raw = os.environ.get("DATABASE_URL", "").strip()
    if not raw:
        # local dev / tests — file next to this module
        here = os.path.dirname(os.path.abspath(__file__))
        return f"sqlite:///{os.path.join(here, 'phishguard.db')}"
    # Neon/Heroku hand out "postgres://"; SQLAlchemy wants "postgresql+psycopg://"
    if raw.startswith("postgres://"):
        raw = "postgresql+psycopg://" + raw[len("postgres://"):]
    elif raw.startswith("postgresql://"):
        raw = "postgresql+psycopg://" + raw[len("postgresql://"):]
    return raw


DATABASE_URL = _database_url()
_is_sqlite = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class Session(Base):
    """One isolated per-browser workspace. The cookie value is this id."""
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    monitoring_active: Mapped[bool] = mapped_column(Boolean, default=True)
    seeded: Mapped[bool] = mapped_column(Boolean, default=False)  # demo inbox planted yet?

    gmail: Mapped[Optional["GmailAccount"]] = relationship(
        back_populates="session", uselist=False, cascade="all, delete-orphan"
    )
    inbox: Mapped[list["InboxItem"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    reports: Mapped[list["IncidentReport"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    session_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("sessions.id", ondelete="CASCADE"), primary_key=True
    )
    email: Mapped[str] = mapped_column(String(320))
    app_password_enc: Mapped[str] = mapped_column(Text)  # Fernet ciphertext, never plaintext
    connected: Mapped[bool] = mapped_column(Boolean, default=False)
    last_scan_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    seen_ids: Mapped[list] = mapped_column(JSON, default=list)  # capped list of Message-IDs

    session: Mapped["Session"] = relationship(back_populates="gmail")


class InboxItem(Base):
    __tablename__ = "inbox_items"

    id: Mapped[str] = mapped_column(String(48), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    message_id: Mapped[str] = mapped_column(String(512), default="")
    sender_address: Mapped[str] = mapped_column(String(320), default="")
    display_name: Mapped[str] = mapped_column(String(320), default="")
    subject: Mapped[str] = mapped_column(Text, default="")
    recipient: Mapped[str] = mapped_column(String(320), default="")
    date_str: Mapped[str] = mapped_column(String(120), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    urls: Mapped[list] = mapped_column(JSON, default=list)
    attachments: Mapped[list] = mapped_column(JSON, default=list)
    spf_status: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    dkim_status: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    dmarc_status: Mapped[str] = mapped_column(String(16), default="UNKNOWN")

    analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="SAFE_INBOX")
    incident_id: Mapped[Optional[str]] = mapped_column(String(48))
    gmail_web_url: Mapped[str] = mapped_column(Text, default="")

    session: Mapped["Session"] = relationship(back_populates="inbox")


class IncidentReport(Base):
    __tablename__ = "incident_reports"

    incident_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    session: Mapped["Session"] = relationship(back_populates="reports")


def init_db() -> None:
    """Bring the schema up to date.

    Postgres (prod): run Alembic migrations to ``head``. SQLite (dev / tests):
    just ``create_all`` — fast, and the dev DB is disposable.
    """
    if _is_sqlite:
        Base.metadata.create_all(engine)
        return

    import os

    from alembic import command
    from alembic.config import Config

    here = os.path.dirname(os.path.abspath(__file__))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "migrations"))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))

    # If the DB already has our tables but no alembic_version (the pre-migrations
    # deploy), stamp the baseline so upgrade() doesn't try to re-create them.
    from sqlalchemy import inspect

    insp = inspect(engine)
    tables = set(insp.get_table_names())
    if "sessions" in tables and "alembic_version" not in tables:
        command.stamp(cfg, "base")
        command.stamp(cfg, "db677a4ee2fb")  # baseline revision
    command.upgrade(cfg, "head")
