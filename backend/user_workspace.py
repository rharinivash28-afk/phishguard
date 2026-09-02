"""Per-session workspace — the isolated replacement for the old global
`SentinelInboxManager`. Every method is scoped to one `session_id` and reads /
writes Postgres (or the dev SQLite file) instead of process memory.
"""
import datetime
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from analyzer import PhishingInvestigationEngine
from crypto import decrypt, encrypt
from db import GmailAccount, IncidentReport, InboxItem, Session
from gmail_service import (
    GmailAuthError, GmailTransientError, fetch_new_messages, validate_app_password,
)
from report_generator import CybercrimeIncidentReportGenerator
from test_samples import SAMPLE_EMAILS

_engine = PhishingInvestigationEngine()
_SEEN_CAP = 500
_BODY_CAP = 20_000       # chars of email body persisted per message
_LIST_CAP = 50           # max urls / attachments stored per message
_MAX_CONSECUTIVE_FAILURES = 5   # transient failures before we give up and disconnect
QUARANTINE_THRESHOLD = 50
VALID_DURATIONS = (1, 4, 12, 24, None)   # hours; None == Permanent


class UserWorkspace:
    def __init__(self, session_id: str, db: OrmSession):
        self.session_id = session_id
        self.db = db

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _session(self) -> Session:
        row = self.db.get(Session, self.session_id)
        if row is None:  # should never happen — dependency guarantees it
            row = Session(id=self.session_id)
            self.db.add(row)
            self.db.commit()
        return row

    def _gmail(self) -> Optional[GmailAccount]:
        return self.db.get(GmailAccount, self.session_id)

    def _item_to_dict(self, it: InboxItem) -> Dict[str, Any]:
        return {
            "id": it.id,
            "title": it.subject and f"Email: {it.subject[:25]}" or "Email",
            "sender_address": it.sender_address,
            "display_name": it.display_name,
            "subject": it.subject,
            "recipient": it.recipient,
            "date": it.date_str,
            "body": it.body,
            "urls": it.urls or [],
            "attachments": it.attachments or [],
            "spf_status": it.spf_status,
            "dkim_status": it.dkim_status,
            "dmarc_status": it.dmarc_status,
            "analysis": it.analysis or {},
            "is_quarantined": it.is_quarantined,
            "incident_id": it.incident_id,
            "status": it.status,
            "gmail_web_url": it.gmail_web_url,
            "message_id": it.message_id,
        }

    # ------------------------------------------------------------------
    # ingest / analyze
    # ------------------------------------------------------------------
    def _ingest(self, email_data: Dict[str, Any], *, from_seed: bool = False) -> InboxItem:
        # bound what we persist per message so one big email can't bloat the DB
        email_data = dict(email_data)
        if isinstance(email_data.get("body"), str) and len(email_data["body"]) > _BODY_CAP:
            email_data["body"] = email_data["body"][:_BODY_CAP] + "\n…[truncated]"
        if isinstance(email_data.get("urls"), list):
            email_data["urls"] = email_data["urls"][:_LIST_CAP]
        if isinstance(email_data.get("attachments"), list):
            email_data["attachments"] = email_data["attachments"][:_LIST_CAP]

        analysis = _engine.investigate(email_data)
        is_quarantined = analysis["risk_score"] >= QUARANTINE_THRESHOLD

        incident_id = None
        if is_quarantined:
            report = CybercrimeIncidentReportGenerator.generate_report(
                analysis, email_data, workspace_id=self.session_id
            )
            incident_id = report["incident_id"]
            existing = self.db.get(IncidentReport, incident_id)
            if existing is None:
                self.db.add(IncidentReport(
                    incident_id=incident_id, session_id=self.session_id, payload=report,
                ))
            elif existing.session_id != self.session_id:
                # extremely unlikely now (id is workspace-salted) but stay safe:
                # never hand another workspace's row to this one
                incident_id = f"{incident_id}-{uuid.uuid4().hex[:4].upper()}"
                self.db.add(IncidentReport(
                    incident_id=incident_id, session_id=self.session_id, payload=report,
                ))

        gmail_web_url = email_data.get("gmail_web_url")
        if not gmail_web_url:
            q = urllib.parse.quote(
                f"from:{email_data.get('sender_address', '')} {email_data.get('subject', '')}"
            )
            gmail_web_url = f"https://mail.google.com/mail/u/0/#search/{q}"

        item = InboxItem(
            id=email_data.get("id") or f"msg_{uuid.uuid4().hex[:10]}",
            session_id=self.session_id,
            message_id=email_data.get("message_id") or f"msg_{uuid.uuid4().hex[:8]}@gmail.com",
            sender_address=email_data.get("sender_address", ""),
            display_name=email_data.get("display_name", ""),
            subject=email_data.get("subject", ""),
            recipient=email_data.get("recipient") or "",
            date_str=str(email_data.get("date") or time.strftime("%Y-%m-%d %H:%M")),
            body=email_data.get("body", ""),
            urls=email_data.get("urls", []),
            attachments=email_data.get("attachments", []),
            spf_status=email_data.get("spf_status", "UNKNOWN"),
            dkim_status=email_data.get("dkim_status", "UNKNOWN"),
            dmarc_status=email_data.get("dmarc_status", "UNKNOWN"),
            analysis=analysis,
            is_quarantined=is_quarantined,
            status="BLOCKED_QUARANTINED" if is_quarantined else "SAFE_INBOX",
            incident_id=incident_id,
            gmail_web_url=gmail_web_url,
        )
        # de-dupe on id collision (seed re-run, retries)
        if self.db.get(InboxItem, item.id) is not None:
            item.id = f"{item.id}_{uuid.uuid4().hex[:4]}"
        self.db.add(item)
        if not from_seed:
            self.db.commit()
        return item

    def process_new_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        item = self._ingest(email_data)
        return self._item_to_dict(item)

    def analyze_only(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Score without persisting (used by the Deep Forensics workbench)."""
        return _engine.investigate(email_data)

    def analyze_and_report(self, email_data: Dict[str, Any]):
        """Score + build a cybercrime dossier, persisting it to this workspace's
        report list so it also shows in the Reports tab. Returns (analysis, report)."""
        analysis = _engine.investigate(email_data)
        report = CybercrimeIncidentReportGenerator.generate_report(
            analysis, email_data, workspace_id=self.session_id
        )
        incident_id = report["incident_id"]
        existing = self.db.get(IncidentReport, incident_id)
        if existing is None:
            self.db.add(IncidentReport(
                incident_id=incident_id, session_id=self.session_id, payload=report,
            ))
            self.db.commit()
        elif existing.session_id == self.session_id:
            existing.payload = report
            self.db.commit()
        return analysis, report

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------
    def list_inbox(self) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            select(InboxItem)
            .where(InboxItem.session_id == self.session_id)
            .order_by(InboxItem.created_at.desc())
        ).scalars().all()
        return [self._item_to_dict(r) for r in rows]

    def list_quarantine(self) -> List[Dict[str, Any]]:
        return [it for it in self.list_inbox() if it["is_quarantined"]]

    def list_reports(self) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            select(IncidentReport)
            .where(IncidentReport.session_id == self.session_id)
            .order_by(IncidentReport.created_at.desc())
        ).scalars().all()
        return [r.payload for r in rows]

    def get_report(self, incident_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.get(IncidentReport, incident_id)
        if row and row.session_id == self.session_id:
            return row.payload
        return None

    def get_stats(self) -> Dict[str, Any]:
        sess = self._session()
        gmail = self._gmail()
        items = self.db.execute(
            select(InboxItem).where(InboxItem.session_id == self.session_id)
        ).scalars().all()
        total = len(items)
        threats = sum(1 for i in items if (i.analysis or {}).get("risk_score", 0) >= QUARANTINE_THRESHOLD)
        quarantined = sum(1 for i in items if i.is_quarantined)
        connected = bool(gmail and gmail.connected)
        return {
            "total_emails_scanned": total,
            "threats_blocked": threats,
            "currently_quarantined": quarantined,
            "safe_delivered": total - threats,
            "monitoring_active": sess.monitoring_active,
            "monitoring_mode": "LIVE_GMAIL" if connected else "AWAITING_CONNECTION",
            "connected_email": gmail.email if (gmail and connected) else "",
            "connected": connected,
            "imap_connected": connected,
            "last_error": gmail.last_error if gmail else None,
            "last_scan_time": (
                gmail.last_scan_at.strftime("%H:%M:%S") if (gmail and gmail.last_scan_at) else None
            ),
        }

    # ------------------------------------------------------------------
    # connection status + duration
    # ------------------------------------------------------------------
    @staticmethod
    def _aware(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
        if dt is not None and dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    def _expires_at(self, gmail: GmailAccount) -> Optional[datetime.datetime]:
        if gmail.duration_hours is None or gmail.connected_at is None:
            return None
        return self._aware(gmail.connected_at) + datetime.timedelta(hours=gmail.duration_hours)

    def connection_status(self) -> Dict[str, Any]:
        gmail = self._gmail()
        if gmail is None or not gmail.connected:
            return {"connected": False, "status": "AWAITING_CONNECTION"}
        # enforce first so an expired connection reports as gone
        if self._enforce_duration():
            return {"connected": False, "status": "EXPIRED"}
        exp = self._expires_at(gmail)
        seconds_remaining = None
        if exp is not None:
            seconds_remaining = max(0, int((exp - _dbnow()).total_seconds()))
        return {
            "connected": True,
            "status": "LIVE_GMAIL",
            "email": gmail.email,
            "connected_at": self._aware(gmail.connected_at).isoformat() if gmail.connected_at else None,
            "duration_hours": gmail.duration_hours,
            "expires_at": exp.isoformat() if exp is not None else None,
            "seconds_remaining": seconds_remaining,
            "permanent": gmail.duration_hours is None,
            "last_scan_at": self._aware(gmail.last_scan_at).isoformat() if gmail.last_scan_at else None,
            "last_error": gmail.last_error,
            "consecutive_failures": gmail.consecutive_failures or 0,
        }

    def _enforce_duration(self) -> bool:
        """If the connection has outlived its duration, tear it down. Returns
        True when an expiry teardown happened."""
        gmail = self._gmail()
        if gmail is None or not gmail.connected:
            return False
        exp = self._expires_at(gmail)
        if exp is not None and _dbnow() >= exp:
            self.db.delete(gmail)
            self._wipe_mail()
            self.db.commit()
            return True
        return False

    # ------------------------------------------------------------------
    # mutations
    # ------------------------------------------------------------------
    def toggle_quarantine(self, item_id: str, action: str) -> Optional[Dict[str, Any]]:
        it = self.db.get(InboxItem, item_id)
        if it is None or it.session_id != self.session_id:
            return None
        if action == "unquarantine":
            it.is_quarantined = False
            it.status = "MANUALLY_RELEASED"
        elif action == "quarantine":
            it.is_quarantined = True
            it.status = "BLOCKED_QUARANTINED"
        self.db.commit()
        return self._item_to_dict(it)

    def set_monitoring_active(self, active: bool) -> Dict[str, Any]:
        sess = self._session()
        sess.monitoring_active = bool(active)
        self.db.commit()
        return {"active": sess.monitoring_active}

    def simulate_incoming(self, sample_id: Optional[str] = None) -> Dict[str, Any]:
        """Inject a demo email. With no sample_id, rotate through the bundled
        samples so repeated clicks don't produce identical rows."""
        if sample_id:
            target = next((dict(s) for s in SAMPLE_EMAILS if s["id"] == sample_id), None)
        else:
            # pick a sample this workspace hasn't simulated yet (by title), else random
            seen_titles = {
                r.subject for r in self.db.execute(
                    select(InboxItem).where(
                        InboxItem.session_id == self.session_id,
                        InboxItem.id.like("live_sim_%"),
                    )
                ).scalars().all()
            }
            fresh = [s for s in SAMPLE_EMAILS if s["subject"] not in seen_titles]
            pool = fresh or SAMPLE_EMAILS
            target = dict(pool[int(time.time()) % len(pool)])
        if target is None:
            target = dict(SAMPLE_EMAILS[0])
        target = dict(target)
        target["id"] = f"live_sim_{int(time.time())}_{uuid.uuid4().hex[:4]}"
        target["date"] = "Just now (Live Threat)"
        return self.process_new_email(target)

    # ------------------------------------------------------------------
    # Gmail connection (app password only)
    # ------------------------------------------------------------------
    def connect_gmail(
        self, email_addr: str, app_password: str, duration_hours: Optional[int] = 24
    ) -> Dict[str, Any]:
        email_addr = (email_addr or "").strip()
        if not email_addr:
            return {"connected": False, "error": "Enter your Gmail address.", "phases": []}
        if duration_hours not in VALID_DURATIONS:
            duration_hours = 24

        try:
            clean_pw = validate_app_password(app_password)
        except GmailAuthError as e:
            return {"connected": False, "error": e.message, "phases": []}

        phases: List[Dict[str, Any]] = []
        new_msgs = None
        transient_note = None
        try:
            new_msgs = fetch_new_messages(email_addr, clean_pw, set(), phases=phases)
        except GmailAuthError as e:
            return {"connected": False, "error": e.message, "raw_error": e.raw, "phases": phases}
        except GmailTransientError as e:
            # one retry before we give up on the initial connect
            time.sleep(1.5)
            phases = []
            try:
                new_msgs = fetch_new_messages(email_addr, clean_pw, set(), phases=phases)
            except GmailAuthError as e2:
                return {"connected": False, "error": e2.message, "raw_error": e2.raw, "phases": phases}
            except GmailTransientError as e2:
                # network is flaky right now — accept the credentials, first sync pending
                transient_note = "Connected — first sync is pending, the network was slow to respond."

        acct = self._save_gmail(
            email_addr, clean_pw, connected=True, error=transient_note,
            duration_hours=duration_hours,
        )
        # fresh mailbox for this account — purge anything that was here before
        self._wipe_mail()
        seen = set()
        count = 0
        for payload in (new_msgs or []):
            self._ingest(payload)
            seen.add(payload["message_id"])
            count += 1
        acct.seen_ids = list(seen)[-_SEEN_CAP:]
        acct.last_scan_at = _dbnow() if new_msgs is not None else None
        acct.consecutive_failures = 0
        self.db.commit()
        return {
            "connected": True,
            "email": email_addr,
            "new_emails_found": count,
            "duration_hours": duration_hours,
            "phases": phases,
            "note": transient_note,
        }

    def _save_gmail(
        self, email_addr, clean_pw, *, connected, error, duration_hours=None
    ) -> GmailAccount:
        acct = self._gmail()
        if acct is None:
            acct = GmailAccount(
                session_id=self.session_id, email=email_addr,
                app_password_enc=encrypt(clean_pw), seen_ids=[],
            )
            self.db.add(acct)
        else:
            acct.email = email_addr
            acct.app_password_enc = encrypt(clean_pw)
        acct.connected = connected
        acct.last_error = error
        acct.connected_at = _dbnow()
        acct.duration_hours = duration_hours
        acct.consecutive_failures = 0
        self.db.commit()
        return acct

    def disconnect_gmail(self) -> Dict[str, Any]:
        acct = self._gmail()
        if acct is not None:
            self.db.delete(acct)
        self._wipe_mail()
        self.db.commit()
        return {"status": "DISCONNECTED"}

    def poll_live_gmail(self) -> Dict[str, Any]:
        acct = self._gmail()
        if acct is None or not acct.connected:
            return {"status": "NOT_CONNECTED", "new_emails_found": 0}

        if self._enforce_duration():
            return {"status": "EXPIRED", "new_emails_found": 0}

        pw = decrypt(acct.app_password_enc)
        seen = set(acct.seen_ids or [])
        try:
            new_msgs = fetch_new_messages(acct.email, pw, seen)
        except GmailAuthError as e:
            # real rejection — the credentials are dead
            acct.connected = False
            acct.last_error = e.message
            self.db.commit()
            return {"status": "AUTH_FAILED", "error": e.message, "new_emails_found": 0}
        except GmailTransientError as e:
            # keep the connection alive; only give up after a run of failures
            acct.consecutive_failures = (acct.consecutive_failures or 0) + 1
            if acct.consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                acct.connected = False
                acct.last_error = (
                    "Lost the connection to Gmail after several retries — please reconnect."
                )
                self.db.commit()
                return {"status": "AUTH_FAILED", "error": acct.last_error, "new_emails_found": 0}
            acct.last_error = "Temporary network issue — retrying on the next scan."
            self.db.commit()
            return {
                "status": "TRANSIENT",
                "error": acct.last_error,
                "consecutive_failures": acct.consecutive_failures,
                "new_emails_found": 0,
            }

        count = 0
        for payload in new_msgs:
            self._ingest(payload)
            seen.add(payload["message_id"])
            count += 1
        acct.seen_ids = list(seen)[-_SEEN_CAP:]
        acct.last_scan_at = _dbnow()
        acct.last_error = None
        acct.consecutive_failures = 0
        self.db.commit()
        return {"status": "SUCCESS", "new_emails_found": count}

    # ------------------------------------------------------------------
    # data lifecycle
    # ------------------------------------------------------------------
    def _wipe_mail(self) -> None:
        for it in self.db.execute(
            select(InboxItem).where(InboxItem.session_id == self.session_id)
        ).scalars().all():
            self.db.delete(it)
        for r in self.db.execute(
            select(IncidentReport).where(IncidentReport.session_id == self.session_id)
        ).scalars().all():
            self.db.delete(r)
        self.db.commit()

    def wipe_everything(self) -> None:
        """Delete this session row entirely — cascade removes all its data."""
        sess = self.db.get(Session, self.session_id)
        if sess is not None:
            self.db.delete(sess)
            self.db.commit()


def _dbnow():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)
