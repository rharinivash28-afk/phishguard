import os
import pathlib
from contextlib import asynccontextmanager

import uvicorn
from dotenv import load_dotenv

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
# backend/.env for hand-set local secrets, then the repo-root .env.local that
# `neon link` writes (DATABASE_URL etc.). Neither overrides real env vars (Render).
load_dotenv(os.path.join(_HERE, ".env"))
load_dotenv(os.path.join(_ROOT, ".env.local"))

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session as OrmSession
from typing import List, Optional
import secrets
import time

from db import Session, init_db
from gmail_service import parse_eml_bytes
from middleware import security_headers
from session_store import get_db, require_session
from test_samples import SAMPLE_EMAILS
from user_workspace import UserWorkspace
from poller import run_tick, start_poller

CRON_SECRET = os.environ.get("CRON_SECRET", "").strip()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    start_poller()
    yield


app = FastAPI(
    title="PhishGuard AI — Personal Inbox Sentinel",
    version="4.1.0",
    description="Multi-factor phishing forensics with a private per-user workspace and Gmail app-password monitoring.",
    lifespan=lifespan,
)

# ---- rate limiting (in-memory; one dyno) --------------------------------------
# RATE_LIMIT_ENABLED=0 turns it off for tests / local load work.
_RL_ON = os.environ.get("RATE_LIMIT_ENABLED", "1").lower() not in ("0", "false", "no")


def _client_key(request: Request) -> str:
    """Real client IP — Render/Fly sit behind a proxy so trust X-Forwarded-For."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(
    key_func=_client_key,
    default_limits=["120/minute"] if _RL_ON else [],
    enabled=_RL_ON,
    headers_enabled=False,  # routes return plain dicts; header injection would break them
)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests — slow down and try again in a minute."},
    )


app.middleware("http")(security_headers)

# Same-origin in prod (the UI is served from this process). Localhost:5173 in dev
# for the Vite dev server. Override with CORS_ALLOW_ORIGINS (comma-separated).
_cors_env = os.environ.get("CORS_ALLOW_ORIGINS", "").strip()
if _cors_env:
    _allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
elif os.environ.get("RENDER") or os.environ.get("PORT") or os.environ.get("FLY_APP_NAME"):
    _allowed_origins = []
else:
    _allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# request models
# ---------------------------------------------------------------------------
class UrlItem(BaseModel):
    url: str
    anchor: Optional[str] = ""


class AttachmentItem(BaseModel):
    filename: str
    size: Optional[int] = 0
    sha256: Optional[str] = None


class EmailInvestigationRequest(BaseModel):
    sender_address: str
    display_name: Optional[str] = ""
    subject: str
    body: str
    recipient: Optional[str] = ""
    urls: Optional[List[UrlItem]] = []
    attachments: Optional[List[AttachmentItem]] = []
    spf_status: Optional[str] = "UNKNOWN"
    dkim_status: Optional[str] = "UNKNOWN"
    dmarc_status: Optional[str] = "UNKNOWN"


class GmailConnectRequest(BaseModel):
    email: str
    app_password: str


class QuarantineActionRequest(BaseModel):
    email_id: str
    action: str


class ToggleMonitoringRequest(BaseModel):
    active: bool


# convenience: build a workspace for the current session
def workspace(
    session: Session = Depends(require_session),
    db: OrmSession = Depends(get_db),
) -> UserWorkspace:
    ws = UserWorkspace(session.id, db)
    ws.ensure_seeded()
    return ws


def _session_expiry_days(session: Session) -> Optional[int]:
    """Days until this session is swept for inactivity — only when < 3 (a nudge)."""
    import datetime

    from session_store import TTL_DAYS

    last = session.last_seen_at
    if last is None:
        return None
    if last.tzinfo is None:
        last = last.replace(tzinfo=datetime.timezone.utc)
    remaining = TTL_DAYS - (datetime.datetime.now(datetime.timezone.utc) - last).days
    return remaining if remaining < 3 else None


# ---------------------------------------------------------------------------
# meta
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health_check():
    return {"status": "ONLINE", "service": "PhishGuard Security Engine", "timestamp": time.time()}


@app.get("/api/config")
def get_public_config():
    return {"version": app.version, "gmail_method": "app_password"}


@app.get("/api/session")
@limiter.limit("30/minute")
def touch_session(request: Request, session: Session = Depends(require_session)):
    """Called on first load so the cookie is set before polling begins."""
    out = {"session": session.id[:8], "monitoring_active": session.monitoring_active}
    expires_in = _session_expiry_days(session)
    if expires_in is not None:
        out["expires_in_days"] = expires_in
    return out


@app.post("/api/session/wipe")
def wipe_session(
    session: Session = Depends(require_session),
    db: OrmSession = Depends(get_db),
):
    UserWorkspace(session.id, db).wipe_everything()
    return {"status": "WIPED"}


@app.get("/api/samples")
def get_sample_emails():
    return {"samples": SAMPLE_EMAILS}


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------
@app.post("/api/analyze")
@limiter.limit("30/minute")
def analyze_email(request: Request, payload: EmailInvestigationRequest, ws: UserWorkspace = Depends(workspace)):
    data = payload.model_dump()
    analysis = ws.analyze_only(data)
    item = ws.process_new_email(data)
    report = ws.get_report(item["incident_id"]) if item.get("incident_id") else None
    return {"analysis": analysis, "incident_report": report, "item": item}


@app.post("/api/generate-report")
@limiter.limit("30/minute")
def generate_report_endpoint(request: Request, payload: EmailInvestigationRequest, ws: UserWorkspace = Depends(workspace)):
    data = payload.model_dump()
    analysis = ws.analyze_only(data)
    from report_generator import CybercrimeIncidentReportGenerator
    report = CybercrimeIncidentReportGenerator.generate_report(analysis, data)
    return {"report": report, "analysis": analysis}


@app.post("/api/upload-eml")
@limiter.limit("30/minute")
async def upload_eml_file(request: Request, file: UploadFile = File(...), ws: UserWorkspace = Depends(workspace)):
    content = await file.read()
    try:
        parsed = parse_eml_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse EML: {e}")
    item = ws.process_new_email(parsed)
    report = ws.get_report(item["incident_id"]) if item.get("incident_id") else None
    return {"status": "SUCCESS", "item": item, "analysis": item["analysis"], "incident_report": report}


# ---------------------------------------------------------------------------
# sentinel (per-session inbox)
# ---------------------------------------------------------------------------
@app.get("/api/sentinel/stats")
def get_sentinel_stats(ws: UserWorkspace = Depends(workspace)):
    return ws.get_stats()


@app.get("/api/sentinel/inbox")
def get_sentinel_inbox(ws: UserWorkspace = Depends(workspace)):
    return {"inbox": ws.list_inbox(), "quarantined": ws.list_quarantine(), "stats": ws.get_stats()}


@app.get("/api/sentinel/reports")
def get_sentinel_reports(ws: UserWorkspace = Depends(workspace)):
    return {"reports": ws.list_reports()}


@app.get("/api/sentinel/report/{incident_id}")
def get_incident_report_by_id(incident_id: str, ws: UserWorkspace = Depends(workspace)):
    report = ws.get_report(incident_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Incident report not found")
    return {"report": report}


@app.post("/api/sentinel/toggle-active")
def toggle_monitoring(payload: ToggleMonitoringRequest, ws: UserWorkspace = Depends(workspace)):
    return ws.set_monitoring_active(payload.active)


@app.post("/api/sentinel/scan-now")
def trigger_manual_scan(ws: UserWorkspace = Depends(workspace)):
    res = ws.poll_live_gmail()
    return {"result": res, "stats": ws.get_stats()}


@app.post("/api/sentinel/quarantine-action")
def perform_quarantine_action(payload: QuarantineActionRequest, ws: UserWorkspace = Depends(workspace)):
    res = ws.toggle_quarantine(payload.email_id, payload.action)
    if not res:
        raise HTTPException(status_code=404, detail="Email item not found")
    return {"status": "SUCCESS", "item": res, "stats": ws.get_stats()}


@app.post("/api/sentinel/simulate-incoming")
def simulate_incoming_attack(sample_id: Optional[str] = "sample_ps02_paypal", ws: UserWorkspace = Depends(workspace)):
    item = ws.simulate_incoming(sample_id or "sample_ps02_paypal")
    return {"status": "INJECTED_AND_ANALYZED", "item": item, "stats": ws.get_stats()}


# ---------------------------------------------------------------------------
# Gmail connection — app password only
# ---------------------------------------------------------------------------
@app.post("/api/gmail/connect")
@limiter.limit("6/minute")
def connect_gmail(request: Request, payload: GmailConnectRequest, ws: UserWorkspace = Depends(workspace)):
    return ws.connect_gmail(payload.email, payload.app_password)


@app.post("/api/gmail/disconnect")
def disconnect_gmail(ws: UserWorkspace = Depends(workspace)):
    return ws.disconnect_gmail()


@app.post("/api/gmail/sync-now")
def sync_gmail(ws: UserWorkspace = Depends(workspace)):
    res = ws.poll_live_gmail()
    return {"result": res, "stats": ws.get_stats()}


# ---------------------------------------------------------------------------
# external cron — keeps polling alive while the free dyno would otherwise sleep
# ---------------------------------------------------------------------------
@app.post("/api/cron/poll-tick")
def cron_poll_tick(x_cron_key: Optional[str] = Header(default=None)):
    if not CRON_SECRET or not x_cron_key or not secrets.compare_digest(x_cron_key, CRON_SECRET):
        raise HTTPException(status_code=403, detail="Forbidden")
    return run_tick(time_budget_s=25.0)


# ---------------------------------------------------------------------------
# Serve the built React frontend (production single-origin deploy)
# ---------------------------------------------------------------------------
_DIST = pathlib.Path(__file__).resolve().parent.parent / "frontend" / "dist"


def _static_dir_exists() -> bool:
    return _DIST.is_dir() and (_DIST / "index.html").exists()


if _static_dir_exists():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def _serve_index():
        return FileResponse(_DIST / "index.html")

    @app.get("/{full_path:path}", include_in_schema=False)
    def _spa_fallback(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        candidate = _DIST / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_DIST / "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    reload_flag = os.environ.get("RENDER") is None and os.environ.get("PORT") is None
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=reload_flag)
