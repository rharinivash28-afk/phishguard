import os
import uvicorn
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import email
from email.header import decode_header
import time
import re
import uuid
import pathlib
import urllib.parse

from analyzer import PhishingInvestigationEngine, extract_domain
from report_generator import CybercrimeIncidentReportGenerator
from gmail_service import SentinelInboxManager, decode_mime_words
from gmail_oauth_service import GmailOAuthService
from test_samples import SAMPLE_EMAILS

app = FastAPI(
    title="PhishGuard AI - 24/7 Inbox Sentinel & Gmail Integration Platform",
    version="3.5.0",
    description="Enterprise Multi-Factor Phishing Forensics Engine, Auto-Quarantine, and Gmail Ingestion Engine"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = PhishingInvestigationEngine()
sentinel = SentinelInboxManager()
oauth_service = GmailOAuthService(engine, sentinel)

class UrlItem(BaseModel):
    url: str
    anchor: Optional[str] = ""

class AttachmentItem(BaseModel):
    filename: str
    size: Optional[int] = 0

class EmailInvestigationRequest(BaseModel):
    sender_address: str
    display_name: Optional[str] = ""
    subject: str
    body: str
    recipient: Optional[str] = "harinivash28082007@gmail.com"
    urls: Optional[List[UrlItem]] = []
    attachments: Optional[List[AttachmentItem]] = []
    spf_status: Optional[str] = "UNKNOWN"
    dkim_status: Optional[str] = "UNKNOWN"
    dmarc_status: Optional[str] = "UNKNOWN"

class GmailConfigRequest(BaseModel):
    email: str
    app_password: Optional[str] = ""

class QuarantineActionRequest(BaseModel):
    email_id: str
    action: str

class ToggleMonitoringRequest(BaseModel):
    active: bool

class DirectTokenRequest(BaseModel):
    email: str
    access_token: str

class OAuthClientCredsRequest(BaseModel):
    client_id: str
    client_secret: str

# In production (Render/Fly/Docker) the UI is served from this same origin, so redirect
# home with a relative path. In local dev the UI runs on the Vite dev server (:5173).
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "")
_IS_PROD = bool(os.environ.get("RENDER") or os.environ.get("PORT") or os.environ.get("FLY_APP_NAME"))


def _home_redirect(query: str) -> str:
    if FRONTEND_ORIGIN:
        base = FRONTEND_ORIGIN.rstrip("/")
    elif _IS_PROD:
        base = ""  # same-origin, relative
    else:
        base = "http://localhost:5173"
    return f"{base}/?{query}"

@app.get("/api/health")
def health_check():
    return {"status": "ONLINE", "service": "PhishGuard Security Engine", "timestamp": time.time()}

@app.get("/api/samples")
def get_sample_emails():
    return {"samples": SAMPLE_EMAILS}

@app.post("/api/analyze")
def analyze_email(payload: EmailInvestigationRequest):
    data_dict = payload.model_dump()
    analysis = engine.investigate(data_dict)
    report = None
    if analysis["risk_score"] >= 50:
        report = CybercrimeIncidentReportGenerator.generate_report(analysis, data_dict)
    
    # Ingest into sentinel live stream
    item = sentinel.process_new_email(data_dict)
    return {
        "analysis": analysis,
        "incident_report": report,
        "item": item
    }

@app.post("/api/upload-eml")
async def upload_eml_file(file: UploadFile = File(...)):
    content = await file.read()
    try:
        msg = email.message_from_bytes(content)
        subject = decode_mime_words(msg.get("Subject", "No Subject"))
        sender = decode_mime_words(msg.get("From", "Unknown Sender"))
        recipient = decode_mime_words(msg.get("To", "harinivash28082007@gmail.com"))
        date_hdr = msg.get("Date", time.strftime("%Y-%m-%d %H:%M"))
        
        display_name = sender.split("<")[0].strip().replace('"', '') if "<" in sender else sender
        clean_sender = sender.split("<")[-1].strip(">").strip() if "<" in sender else sender
        
        body = ""
        urls = []
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" in content_disposition:
                    filename = decode_mime_words(part.get_filename() or "attachment.bin")
                    attachments.append({"filename": filename, "size": len(part.get_payload(decode=True) or b"")})
                elif content_type == "text/plain" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="ignore")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")

        # Extract URLs
        extracted_urls = re.findall(r'https?://[^\s<>"\'\)]+', body)
        urls = [{"url": u, "anchor": ""} for u in extracted_urls]

        # Authentication headers
        auth_res = msg.get("Authentication-Results", "").lower()
        received_spf = msg.get("Received-SPF", "").lower()
        
        spf_status = "PASS" if ("spf=pass" in auth_res or "pass" in received_spf) else ("FAIL" if "spf=fail" in auth_res else "UNKNOWN")
        dkim_status = "PASS" if "dkim=pass" in auth_res else ("FAIL" if "dkim=fail" in auth_res else "UNKNOWN")
        dmarc_status = "PASS" if "dmarc=pass" in auth_res else ("FAIL" if "dmarc=fail" in auth_res else "UNKNOWN")

        gmail_query = urllib.parse.quote(f"from:{clean_sender} {subject}")
        gmail_web_url = f"https://mail.google.com/mail/u/0/#search/{gmail_query}"

        email_payload = {
            "id": f"eml_{uuid.uuid4().hex[:8]}",
            "title": f"Gmail: {subject[:30]}",
            "sender_address": clean_sender,
            "display_name": display_name,
            "subject": subject,
            "recipient": recipient or "harinivash28082007@gmail.com",
            "date": date_hdr,
            "body": body or "No text body found in message.",
            "urls": urls,
            "attachments": attachments,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "gmail_web_url": gmail_web_url
        }

        analysis = engine.investigate(email_payload)
        item = sentinel.process_new_email(email_payload)
        report = None
        if analysis["risk_score"] >= 50:
            report = CybercrimeIncidentReportGenerator.generate_report(analysis, email_payload)

        return {
            "status": "SUCCESS",
            "item": item,
            "analysis": analysis,
            "incident_report": report
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse EML: {str(e)}")

@app.post("/api/generate-report")
def generate_report_endpoint(payload: EmailInvestigationRequest):
    data_dict = payload.model_dump()
    analysis = engine.investigate(data_dict)
    report = CybercrimeIncidentReportGenerator.generate_report(analysis, data_dict)
    return {"report": report, "analysis": analysis}

@app.get("/api/sentinel/stats")
def get_sentinel_stats():
    base_stats = sentinel.get_stats()
    oauth_status = oauth_service.get_oauth_status()
    base_stats["oauth"] = oauth_status
    return base_stats

@app.get("/api/sentinel/inbox")
def get_sentinel_inbox():
    return {
        "inbox": sentinel.inbox_items,
        "quarantined": sentinel.quarantine_items,
        "stats": get_sentinel_stats()
    }

@app.get("/api/sentinel/reports")
def get_sentinel_reports():
    return {"reports": sentinel.generated_reports}

@app.get("/api/sentinel/report/{incident_id}")
def get_incident_report_by_id(incident_id: str):
    for r in sentinel.generated_reports:
        if r.get("incident_id") == incident_id:
            return {"report": r}
    raise HTTPException(status_code=404, detail="Incident report not found")

@app.post("/api/sentinel/toggle-active")
def toggle_monitoring(payload: ToggleMonitoringRequest):
    return sentinel.set_monitoring_active(payload.active)

@app.post("/api/sentinel/scan-now")
def trigger_manual_scan():
    if oauth_service.tokens.get("is_connected"):
        res = oauth_service.fetch_latest_messages_now()
    else:
        res = sentinel.poll_live_gmail()
    return {"result": res, "stats": get_sentinel_stats()}

@app.post("/api/sentinel/quarantine-action")
def perform_quarantine_action(payload: QuarantineActionRequest):
    res = sentinel.toggle_quarantine(payload.email_id, payload.action)
    if not res:
        raise HTTPException(status_code=404, detail="Email item not found")
    return {"status": "SUCCESS", "item": res, "stats": get_sentinel_stats()}

@app.post("/api/sentinel/connect-gmail")
def connect_user_gmail(payload: GmailConfigRequest):
    res = sentinel.connect_gmail(payload.email, payload.app_password or "")
    return res

@app.post("/api/sentinel/simulate-incoming")
def simulate_incoming_attack(sample_id: Optional[str] = "sample_ps02_paypal"):
    target_sample = None
    for s in SAMPLE_EMAILS:
        if s["id"] == sample_id:
            target_sample = dict(s)
            break
    if not target_sample:
        target_sample = dict(SAMPLE_EMAILS[0])
    
    target_sample["id"] = f"live_sim_{int(time.time())}"
    target_sample["date"] = "Just now (Live Threat)"
    target_sample["recipient"] = "harinivash28082007@gmail.com"
    processed = sentinel.process_new_email(target_sample)
    return {"status": "INJECTED_AND_ANALYZED", "item": processed, "stats": get_sentinel_stats()}

# Google OAuth endpoints
@app.post("/api/auth/google/direct-token")
def connect_with_direct_oauth_token(payload: DirectTokenRequest):
    res = oauth_service.connect_with_direct_token(payload.email, payload.access_token)
    return res

@app.post("/api/auth/google/save-credentials")
def save_oauth_client_credentials(payload: OAuthClientCredsRequest):
    return oauth_service.save_client_credentials(payload.client_id, payload.client_secret)

@app.get("/api/auth/google/login")
def start_google_oauth():
    """Return the Google consent URL so the frontend can redirect the user."""
    if not oauth_service.has_client_credentials():
        raise HTTPException(status_code=400, detail="Google OAuth client not configured yet.")
    return {"auth_url": oauth_service.get_auth_url(), "redirect_uri": oauth_service.redirect_uri}

@app.get("/api/auth/google/callback")
def google_oauth_callback(code: Optional[str] = None, error: Optional[str] = None):
    """Google redirects the browser here after consent; exchange the code then bounce home."""
    if error:
        return RedirectResponse(_home_redirect(f"gmail=error&reason={urllib.parse.quote(error)}"))
    if not code:
        return RedirectResponse(_home_redirect("gmail=error&reason=missing_code"))
    res = oauth_service.exchange_code_for_tokens(code)
    if res.get("status") == "SUCCESS":
        return RedirectResponse(_home_redirect(f"gmail=connected&email={urllib.parse.quote(res.get('email', ''))}"))
    return RedirectResponse(_home_redirect(f"gmail=error&reason={urllib.parse.quote(str(res.get('error', 'unknown'))[:180])}"))

@app.get("/api/auth/google/status")
def get_google_oauth_status():
    return oauth_service.get_oauth_status()

@app.post("/api/auth/google/sync-now")
def sync_oauth_gmail():
    res = oauth_service.fetch_latest_messages_now()
    return {"result": res, "stats": get_sentinel_stats()}

@app.post("/api/auth/google/disconnect")
def disconnect_google_oauth():
    return oauth_service.disconnect()

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
        # Never swallow the API namespace
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
