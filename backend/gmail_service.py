import email
from email.header import decode_header
import imaplib
import threading
import time
import uuid
import urllib.parse
from typing import Dict, Any, List, Optional
from analyzer import PhishingInvestigationEngine, extract_domain
from report_generator import CybercrimeIncidentReportGenerator
from test_samples import SAMPLE_EMAILS

def decode_mime_words(s):
    if not s:
        return ""
    try:
        decoded_fragments = decode_header(s)
        result = []
        for fragment, encoding in decoded_fragments:
            if isinstance(fragment, bytes):
                result.append(fragment.decode(encoding or 'utf-8', errors='ignore'))
            else:
                result.append(str(fragment))
        return "".join(result)
    except Exception:
        return str(s)

def clean_credential_str(val: str) -> str:
    if not val:
        return ""
    return val.strip().replace(" ", "").replace("\xa0", "").replace("\r", "").replace("\n", "").replace('"', '').replace("'", "")

class SentinelInboxManager:
    def __init__(self):
        self.engine = PhishingInvestigationEngine()
        self.is_monitoring_active = True
        self.monitoring_mode = "ACTIVE_SENTINEL"
        self.gmail_credentials = {
            "email": "harinivash28082007@gmail.com",
            "app_password": "",
            "connected": False,
            "imap_connected": False,
            "last_error": None,
            "last_scan_time": time.strftime("%H:%M:%S")
        }
        self.inbox_items: List[Dict[str, Any]] = []
        self.quarantine_items: List[Dict[str, Any]] = []
        self.generated_reports: List[Dict[str, Any]] = []
        self.seen_message_ids = set()
        self.monitor_thread = None
        self._lock = threading.RLock()  # reentrant: connect_gmail -> poll_live_gmail -> process_new_email
        
        self._init_default_inbox()
        self._start_background_monitor()

    # ------------------------------------------------------------------
    # Mailbox reset — called whenever a *different* account connects so we
    # never show the previous user's mail.
    # ------------------------------------------------------------------
    def reset_for_account(self, email_addr: str, *, keep_samples: bool = False):
        with self._lock:
            self.inbox_items.clear()
            self.quarantine_items.clear()
            self.generated_reports.clear()
            self.seen_message_ids.clear()
            self.gmail_credentials["email"] = email_addr or self.gmail_credentials["email"]
            self.gmail_credentials["last_error"] = None
            if keep_samples:
                self._init_default_inbox()

    def _init_default_inbox(self):
        for sample in SAMPLE_EMAILS:
            analysis = self.engine.investigate(sample)
            report = None
            is_quarantined = False
            
            if analysis['risk_score'] >= 50:
                is_quarantined = True
                report = CybercrimeIncidentReportGenerator.generate_report(analysis, sample)
                self.generated_reports.append(report)

            gmail_query = urllib.parse.quote(f"from:{sample['sender_address']} {sample['subject']}")
            gmail_web_url = f"https://mail.google.com/mail/u/0/#search/{gmail_query}"

            item = {
                "id": sample["id"],
                "title": sample["title"],
                "sender_address": sample["sender_address"],
                "display_name": sample["display_name"],
                "subject": sample["subject"],
                "recipient": "harinivash28082007@gmail.com",
                "date": sample.get("date", "Just now"),
                "body": sample["body"],
                "urls": sample.get("urls", []),
                "attachments": sample.get("attachments", []),
                "spf_status": sample.get("spf_status", "UNKNOWN"),
                "dkim_status": sample.get("dkim_status", "UNKNOWN"),
                "dmarc_status": sample.get("dmarc_status", "UNKNOWN"),
                "analysis": analysis,
                "is_quarantined": is_quarantined,
                "incident_id": report["incident_id"] if report else None,
                "status": "BLOCKED_QUARANTINED" if is_quarantined else "SAFE_INBOX",
                "gmail_web_url": gmail_web_url,
                "message_id": f"sample_{sample['id']}@mail.gmail.com"
            }
            self.inbox_items.append(item)
            self.seen_message_ids.add(item["message_id"])
            if is_quarantined:
                self.quarantine_items.append(item)

    def _start_background_monitor(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            return
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _monitor_loop(self):
        while True:
            try:
                if self.is_monitoring_active:
                    if self.monitoring_mode == "LIVE_GMAIL" and self.gmail_credentials.get("app_password"):
                        self.poll_live_gmail()
                    time.sleep(12)
                else:
                    time.sleep(5)
            except Exception as e:
                print(f"[Sentinel 24/7 Daemon Loop]: {e}")
                time.sleep(10)

    def poll_live_gmail(self) -> Dict[str, Any]:
        email_addr = self.gmail_credentials.get("email", "harinivash28082007@gmail.com").strip()
        password = clean_credential_str(self.gmail_credentials.get("app_password", ""))

        if not email_addr or not password:
            return {"status": "SKIPPED", "message": "No password configured"}

        # Fast client-side sanity check before we even hit Gmail.
        if len(password) != 16 or not password.isalnum():
            hint = (
                f"That's {len(password)} characters - a Gmail App Password is exactly 16 letters "
                "(no digits, no symbols). You may have pasted your normal account password. "
                "Generate one at myaccount.google.com/apppasswords (needs 2-Step Verification ON)."
            )
            self.gmail_credentials["last_error"] = hint
            return {"status": "AUTH_FAILED", "error": hint, "raw_error": "local_format_check"}

        try:
            imap_server = "imap.gmail.com"
            mail = imaplib.IMAP4_SSL(imap_server, 993, timeout=10)

            try:
                mail.login(email_addr, password)
            except imaplib.IMAP4.error as login_err:
                err_str = str(login_err)
                human_err = (
                    f"Gmail rejected the login for {email_addr}. Most common causes: "
                    "(1) 2-Step Verification is not turned on for this account - turn it on first; "
                    "(2) IMAP is not enabled - Gmail Settings > Forwarding and POP/IMAP > Enable IMAP > Save; "
                    "(3) the App Password was generated for a different Google account; "
                    "(4) you used your normal password instead of a 16-letter App Password. "
                    "Generate a fresh one at myaccount.google.com/apppasswords."
                )
                self.gmail_credentials["last_error"] = human_err
                return {"status": "AUTH_FAILED", "error": human_err, "raw_error": err_str}

            mail.select("INBOX")
            
            status, messages = mail.search(None, "ALL")
            new_count = 0
            
            if status == "OK" and messages[0]:
                msg_ids = messages[0].split()
                for num in msg_ids[-10:]:
                    res, msg_data = mail.fetch(num, "(RFC822)")
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1])
                            message_id = msg.get("Message-ID", f"live_{uuid.uuid4().hex[:10]}")
                            
                            if message_id in self.seen_message_ids:
                                continue
                                
                            self.seen_message_ids.add(message_id)
                            subject = decode_mime_words(msg.get("Subject", "No Subject"))
                            sender = decode_mime_words(msg.get("From", "Unknown"))
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

                            msg_id_clean = message_id.strip("<>").strip()
                            gmail_query = urllib.parse.quote(f"rfc822msgid:{msg_id_clean}")
                            gmail_web_url = f"https://mail.google.com/mail/u/0/#search/{gmail_query}"

                            auth_res = msg.get("Authentication-Results", "")
                            spf_status = "PASS" if "spf=pass" in auth_res.lower() else ("FAIL" if "spf=fail" in auth_res.lower() else "UNKNOWN")
                            dkim_status = "PASS" if "dkim=pass" in auth_res.lower() else ("FAIL" if "dkim=fail" in auth_res.lower() else "UNKNOWN")
                            dmarc_status = "PASS" if "dmarc=pass" in auth_res.lower() else ("FAIL" if "dmarc=fail" in auth_res.lower() else "UNKNOWN")

                            email_payload = {
                                "id": f"live_{uuid.uuid4().hex[:8]}",
                                "title": f"Live: {subject[:30]}",
                                "sender_address": clean_sender,
                                "display_name": display_name,
                                "subject": subject,
                                "recipient": email_addr,
                                "date": date_hdr,
                                "body": body or "No text content",
                                "urls": urls,
                                "attachments": attachments,
                                "spf_status": spf_status,
                                "dkim_status": dkim_status,
                                "dmarc_status": dmarc_status,
                                "message_id": message_id,
                                "gmail_web_url": gmail_web_url
                            }
                            self.process_new_email(email_payload)
                            new_count += 1
            
            mail.close()
            mail.logout()
            self.gmail_credentials["connected"] = True
            self.gmail_credentials["last_error"] = None
            self.gmail_credentials["last_scan_time"] = time.strftime("%H:%M:%S")
            return {"status": "SUCCESS", "new_emails_found": new_count, "last_scan": self.gmail_credentials["last_scan_time"]}
        except Exception as err:
            err_msg = str(err)
            self.gmail_credentials["last_error"] = err_msg
            return {"status": "ERROR", "error": err_msg}

    def process_new_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            analysis = self.engine.investigate(email_data)
            is_quarantined = False
            report = None

            if analysis["risk_score"] >= 50:
                is_quarantined = True
                report = CybercrimeIncidentReportGenerator.generate_report(analysis, email_data)
                self.generated_reports.insert(0, report)

            gmail_web_url = email_data.get("gmail_web_url")
            if not gmail_web_url:
                search_q = urllib.parse.quote(f"from:{email_data.get('sender_address', '')} {email_data.get('subject', '')}")
                gmail_web_url = f"https://mail.google.com/mail/u/0/#search/{search_q}"

            item = {
                "id": email_data.get("id", f"msg_{uuid.uuid4().hex[:8]}"),
                "title": email_data.get("title", f"Email: {email_data.get('subject', '')[:25]}"),
                "sender_address": email_data.get("sender_address", ""),
                "display_name": email_data.get("display_name", ""),
                "subject": email_data.get("subject", ""),
                "recipient": email_data.get("recipient") or self.gmail_credentials.get("email", ""),
                "date": email_data.get("date", time.strftime("%Y-%m-%d %H:%M")),
                "body": email_data.get("body", ""),
                "urls": email_data.get("urls", []),
                "attachments": email_data.get("attachments", []),
                "spf_status": email_data.get("spf_status", "UNKNOWN"),
                "dkim_status": email_data.get("dkim_status", "UNKNOWN"),
                "dmarc_status": email_data.get("dmarc_status", "UNKNOWN"),
                "analysis": analysis,
                "is_quarantined": is_quarantined,
                "incident_id": report["incident_id"] if report else None,
                "status": "BLOCKED_QUARANTINED" if is_quarantined else "SAFE_INBOX",
                "gmail_web_url": gmail_web_url,
                "message_id": email_data.get("message_id", f"msg_{uuid.uuid4().hex[:8]}@gmail.com")
            }

            self.inbox_items.insert(0, item)
            if is_quarantined:
                self.quarantine_items.insert(0, item)

            return item

    def toggle_quarantine(self, item_id: str, action: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for item in self.inbox_items:
                if item["id"] == item_id:
                    if action == "unquarantine":
                        item["is_quarantined"] = False
                        item["status"] = "MANUALLY_RELEASED"
                        self.quarantine_items = [q for q in self.quarantine_items if q["id"] != item_id]
                    elif action == "quarantine":
                        item["is_quarantined"] = True
                        item["status"] = "BLOCKED_QUARANTINED"
                        if not any(q["id"] == item_id for q in self.quarantine_items):
                            self.quarantine_items.insert(0, item)
                    return item
        return None

    def connect_gmail(self, email_addr: str, app_password: str) -> Dict[str, Any]:
        # Only hold the lock for the quick credential mutation - never across the
        # blocking IMAP network call below (that would stall every /stats poll).
        with self._lock:
            clean_email = email_addr.strip() or "harinivash28082007@gmail.com"
            clean_pw = clean_credential_str(app_password)
            self.gmail_credentials["email"] = clean_email
            self.gmail_credentials["app_password"] = clean_pw

        if not clean_pw:
            # just saving an address, not actually connecting -> keep the demo inbox
            with self._lock:
                self.monitoring_mode = "ACTIVE_SENTINEL"
                self.gmail_credentials["connected"] = False
                self.gmail_credentials["imap_connected"] = False
                self.gmail_credentials["last_error"] = None
            return {
                "status": "SUCCESS",
                "email": clean_email,
                "mode": "ACTIVE_SENTINEL",
                "connected": False,
                "active": self.is_monitoring_active,
            }

        # A real connection attempt: clear whatever the previous account left behind.
        self.reset_for_account(clean_email)
        with self._lock:
            self.monitoring_mode = "LIVE_GMAIL"

        # network I/O happens with the lock released
        test_res = self.poll_live_gmail()
        ok = test_res.get("status") == "SUCCESS"

        with self._lock:
            self.gmail_credentials["connected"] = ok
            self.gmail_credentials["imap_connected"] = ok
            if not ok:
                self.monitoring_mode = "ACTIVE_SENTINEL"  # keep creds, fall back
                # nothing was pulled -> give the demo inbox back so the UI isn't blank
                if not self.inbox_items:
                    self._init_default_inbox()
            mode = self.monitoring_mode
            active = self.is_monitoring_active

        return {
            "status": test_res.get("status", "SUCCESS"),
            "email": clean_email,
            "mode": "LIVE_GMAIL" if ok else mode,
            "connected": ok,
            "active": active,
            "new_emails_found": test_res.get("new_emails_found", 0),
            "error": test_res.get("error"),
            "raw_error": test_res.get("raw_error"),
        }

    def set_monitoring_active(self, active: bool):
        with self._lock:
            self.is_monitoring_active = active
            return {"active": self.is_monitoring_active}

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self.inbox_items)
            quarantined = len(self.quarantine_items)
            threats = sum(1 for i in self.inbox_items if i.get("analysis", {}).get("risk_score", 0) >= 50)
            safe = total - threats
            return {
                "total_emails_scanned": total,
                "threats_blocked": threats,
                "currently_quarantined": quarantined,
                "safe_delivered": safe,
                "monitoring_active": self.is_monitoring_active,
                "monitoring_mode": self.monitoring_mode,
                "connected_email": self.gmail_credentials.get("email", "harinivash28082007@gmail.com"),
                "connected": bool(self.gmail_credentials.get("connected")),
                "imap_connected": bool(self.gmail_credentials.get("imap_connected")),
                "last_error": self.gmail_credentials.get("last_error"),
                "last_scan_time": self.gmail_credentials.get("last_scan_time")
            }
