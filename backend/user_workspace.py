"""Per-session workspace — the isolated replacement for the old global
`SentinelInboxManager`. Every method is scoped to one `session_id` and reads /
writes Postgres (or the dev SQLite file) instead of process memory.
"""
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from analyzer import PhishingInvestigationEngine
from crypto import decrypt, encrypt
from db import GmailAccount, IncidentReport, InboxItem, Session
from gmail_service import GmailAuthError, fetch_new_messages, validate_app_password
from report_generator import CybercrimeIncidentReportGenerator
from test_samples import SAMPLE_EMAILS

_engine = PhishingInvestigationEngine()
_SEEN_CAP = 500
_BODY_CAP = 20_000       # chars of email body persisted per message
_LIST_CAP = 50           # max urls / attachments stored per message
QUARANTINE_THRESHOLD = 50


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
    # demo seed — planted once so a brand-new user isn't staring at nothing
    # ------------------------------------------------------------------
    def ensure_seeded(self) -> None:
        sess = self._session()
        if sess.seeded:
            return
        for sample in SAMPLE_EMAILS:
            self._ingest(dict(sample), from_seed=True)
        sess.seeded = True
        self.db.commit()

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
            report = CybercrimeIncidentReportGenerator.generate_report(analysis, email_data)
            incident_id = report["incident_id"]
            if self.db.get(IncidentReport, incident_id) is None:
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
        return {
            "total_emails_scanned": total,
            "threats_blocked": threats,
            "currently_quarantined": quarantined,
            "safe_delivered": total - threats,
            "monitoring_active": sess.monitoring_active,
            "monitoring_mode": "LIVE_GMAIL" if (gmail and gmail.connected) else "DEMO",
            "connected_email": gmail.email if gmail else "",
            "connected": bool(gmail and gmail.connected),
            "imap_connected": bool(gmail and gmail.connected),
            "last_error": gmail.last_error if gmail else None,
            "last_scan_time": (
                gmail.last_scan_at.strftime("%H:%M:%S") if (gmail and gmail.last_scan_at) else None
            ),
        }

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

    def simulate_incoming(self, sample_id: str = "sample_ps02_paypal") -> Dict[str, Any]:
        target = next((dict(s) for s in SAMPLE_EMAILS if s["id"] == sample_id), None)
        if target is None:
            target = dict(SAMPLE_EMAILS[0])
        target["id"] = f"live_sim_{int(time.time())}_{uuid.uuid4().hex[:4]}"
        target["date"] = "Just now (Live Threat)"
        return self.process_new_email(target)

    # ------------------------------------------------------------------
    # Gmail connection (app password only)
    # ------------------------------------------------------------------
    def connect_gmail(self, email_addr: str, app_password: str) -> Dict[str, Any]:
        email_addr = (email_addr or "").strip()
        if not email_addr:
            return {"connected": False, "error": "Enter your Gmail address."}

        try:
            clean_pw = validate_app_password(app_password)
        except GmailAuthError as e:
            return {"connected": False, "error": e.message}

        # test the connection immediately
        try:
            new_msgs = fetch_new_messages(email_addr, clean_pw, set())
        except GmailAuthError as e:
            self._save_gmail(email_addr, clean_pw, connected=False, error=e.message)
            return {"connected": False, "error": e.message, "raw_error": e.raw}
        except Exception as e:  # transport / timeout
            msg = f"Could not reach Gmail: {e}"
            self._save_gmail(email_addr, clean_pw, connected=False, error=msg)
            return {"connected": False, "error": msg}

        # success — fresh mailbox for this account
        self._wipe_mail(keep_seed=False)
        acct = self._save_gmail(email_addr, clean_pw, connected=True, error=None)
        seen = set(acct.seen_ids or [])
        count = 0
        for payload in new_msgs:
            self._ingest(payload)
            seen.add(payload["message_id"])
            count += 1
        acct.seen_ids = list(seen)[-_SEEN_CAP:]
        acct.last_scan_at = _dbnow()
        self.db.commit()
        return {"connected": True, "email": email_addr, "new_emails_found": count}

    def _save_gmail(self, email_addr, clean_pw, *, connected, error) -> GmailAccount:
        acct = self._gmail()
        if acct is None:
            acct = GmailAccount(session_id=self.session_id, email=email_addr,
                                app_password_enc=encrypt(clean_pw), seen_ids=[])
            self.db.add(acct)
        else:
            acct.email = email_addr
            acct.app_password_enc = encrypt(clean_pw)
        acct.connected = connected
        acct.last_error = error
        self.db.commit()
        return acct

    def disconnect_gmail(self) -> Dict[str, Any]:
        acct = self._gmail()
        if acct is not None:
            self.db.delete(acct)
        self._wipe_mail(keep_seed=True)
        self.db.commit()
        return {"status": "DISCONNECTED"}

    def poll_live_gmail(self) -> Dict[str, Any]:
        acct = self._gmail()
        if acct is None or not acct.connected:
            return {"status": "NOT_CONNECTED", "new_emails_found": 0}
        pw = decrypt(acct.app_password_enc)
        seen = set(acct.seen_ids or [])
        try:
            new_msgs = fetch_new_messages(acct.email, pw, seen)
        except GmailAuthError as e:
            acct.connected = False
            acct.last_error = e.message
            self.db.commit()
            return {"status": "AUTH_FAILED", "error": e.message, "new_emails_found": 0}
        except Exception as e:
            acct.last_error = str(e)
            self.db.commit()
            return {"status": "ERROR", "error": str(e), "new_emails_found": 0}

        count = 0
        for payload in new_msgs:
            self._ingest(payload)
            seen.add(payload["message_id"])
            count += 1
        acct.seen_ids = list(seen)[-_SEEN_CAP:]
        acct.last_scan_at = _dbnow()
        acct.last_error = None
        self.db.commit()
        return {"status": "SUCCESS", "new_emails_found": count}

    # ------------------------------------------------------------------
    # data lifecycle
    # ------------------------------------------------------------------
    def _wipe_mail(self, *, keep_seed: bool) -> None:
        for it in self.db.execute(
            select(InboxItem).where(InboxItem.session_id == self.session_id)
        ).scalars().all():
            self.db.delete(it)
        for r in self.db.execute(
            select(IncidentReport).where(IncidentReport.session_id == self.session_id)
        ).scalars().all():
            self.db.delete(r)
        sess = self._session()
        sess.seeded = False
        self.db.commit()
        if keep_seed:
            self.ensure_seeded()

    def wipe_everything(self) -> None:
        """Delete this session row entirely — cascade removes all its data."""
        sess = self.db.get(Session, self.session_id)
        if sess is not None:
            self.db.delete(sess)
            self.db.commit()


def _dbnow():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)
