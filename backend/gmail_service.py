"""Gmail IMAP access — pure, stateless helpers.

The per-user stateful workspace lives in `user_workspace.py`; this module only
knows how to talk to Gmail over IMAP and turn a raw message into the dict shape
the analyzer expects.
"""
import email
import imaplib
import re
import time
import urllib.parse
import uuid
from email.header import decode_header
from typing import Any, Dict, List


def decode_mime_words(s) -> str:
    if not s:
        return ""
    try:
        result = []
        for fragment, enc in decode_header(s):
            if isinstance(fragment, bytes):
                result.append(fragment.decode(enc or "utf-8", errors="ignore"))
            else:
                result.append(str(fragment))
        return "".join(result)
    except Exception:
        return str(s)


def clean_credential_str(val: str) -> str:
    if not val:
        return ""
    return (
        val.strip()
        .replace(" ", "").replace("\xa0", "").replace("\r", "").replace("\n", "")
        .replace('"', "").replace("'", "")
    )


class GmailAuthError(Exception):
    """Raised when Gmail rejects the login — carries a human-readable hint."""

    def __init__(self, message: str, raw: str = ""):
        super().__init__(message)
        self.message = message
        self.raw = raw


def validate_app_password(app_password: str) -> str:
    """Fast local sanity check. Returns cleaned pw or raises GmailAuthError."""
    pw = clean_credential_str(app_password)
    if len(pw) != 16 or not pw.isalnum():
        raise GmailAuthError(
            f"That's {len(pw)} characters — a Gmail App Password is exactly 16 letters "
            "(no digits, no symbols). You may have pasted your normal account password. "
            "Generate one at myaccount.google.com/apppasswords (needs 2-Step Verification ON)."
        )
    return pw


def _parse_message(msg, email_addr: str) -> Dict[str, Any]:
    message_id = msg.get("Message-ID", f"live_{uuid.uuid4().hex[:10]}")
    subject = decode_mime_words(msg.get("Subject", "No Subject"))
    sender = decode_mime_words(msg.get("From", "Unknown"))
    date_hdr = msg.get("Date", time.strftime("%Y-%m-%d %H:%M"))

    display_name = sender.split("<")[0].strip().replace('"', "") if "<" in sender else sender
    clean_sender = sender.split("<")[-1].strip(">").strip() if "<" in sender else sender

    body = ""
    attachments: List[Dict[str, Any]] = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition"))
            if "attachment" in disposition:
                filename = decode_mime_words(part.get_filename() or "attachment.bin")
                attachments.append(
                    {"filename": filename, "size": len(part.get_payload(decode=True) or b"")}
                )
            elif content_type == "text/plain" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")

    urls = [{"url": u, "anchor": ""} for u in re.findall(r'https?://[^\s<>"\'\)]+', body)]

    auth_res = msg.get("Authentication-Results", "").lower()
    spf = "PASS" if "spf=pass" in auth_res else ("FAIL" if "spf=fail" in auth_res else "UNKNOWN")
    dkim = "PASS" if "dkim=pass" in auth_res else ("FAIL" if "dkim=fail" in auth_res else "UNKNOWN")
    dmarc = "PASS" if "dmarc=pass" in auth_res else ("FAIL" if "dmarc=fail" in auth_res else "UNKNOWN")

    msg_id_clean = message_id.strip("<>").strip()
    gmail_web_url = (
        "https://mail.google.com/mail/u/0/#search/"
        + urllib.parse.quote(f"rfc822msgid:{msg_id_clean}")
    )

    return {
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
        "spf_status": spf,
        "dkim_status": dkim,
        "dmarc_status": dmarc,
        "message_id": message_id,
        "gmail_web_url": gmail_web_url,
    }


def parse_eml_bytes(content: bytes, fallback_recipient: str = "") -> Dict[str, Any]:
    """Turn a downloaded .eml file into the analyzer's email dict shape."""
    msg = email.message_from_bytes(content)
    parsed = _parse_message(msg, fallback_recipient or decode_mime_words(msg.get("To", "")))
    parsed["id"] = f"eml_{uuid.uuid4().hex[:8]}"
    parsed["title"] = f"Gmail: {parsed['subject'][:30]}"
    if not parsed["body"] or parsed["body"] == "No text content":
        parsed["body"] = "No text body found in message."
    # .eml files also carry Received-SPF sometimes
    received_spf = msg.get("Received-SPF", "").lower()
    if parsed["spf_status"] == "UNKNOWN" and "pass" in received_spf:
        parsed["spf_status"] = "PASS"
    return parsed


def fetch_new_messages(
    email_addr: str, app_password: str, seen_ids: set, *, limit: int = 12
) -> List[Dict[str, Any]]:
    """Connect to Gmail over IMAP, return parsed dicts for messages not in seen_ids.

    Raises GmailAuthError on a login failure (with a user-facing hint),
    or a plain Exception on a transport error.
    """
    pw = validate_app_password(app_password)
    email_addr = (email_addr or "").strip()
    if not email_addr:
        raise GmailAuthError("No Gmail address provided.")

    mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=12)
    try:
        try:
            mail.login(email_addr, pw)
        except imaplib.IMAP4.error as login_err:
            raise GmailAuthError(
                f"Gmail rejected the login for {email_addr}. Most common causes: "
                "(1) 2-Step Verification is not turned on — turn it on first; "
                "(2) IMAP is not enabled — Gmail Settings > Forwarding and POP/IMAP > Enable IMAP > Save; "
                "(3) the App Password was generated for a different Google account; "
                "(4) you used your normal password instead of a 16-letter App Password. "
                "Generate a fresh one at myaccount.google.com/apppasswords.",
                raw=str(login_err),
            )

        mail.select("INBOX")
        status, messages = mail.search(None, "ALL")
        out: List[Dict[str, Any]] = []
        if status == "OK" and messages and messages[0]:
            for num in messages[0].split()[-limit:]:
                res, msg_data = mail.fetch(num, "(RFC822)")
                for part in msg_data:
                    if not isinstance(part, tuple):
                        continue
                    msg = email.message_from_bytes(part[1])
                    mid = msg.get("Message-ID", f"live_{uuid.uuid4().hex[:10]}")
                    if mid in seen_ids:
                        continue
                    out.append(_parse_message(msg, email_addr))
        return out
    finally:
        try:
            mail.close()
        except Exception:
            pass
        try:
            mail.logout()
        except Exception:
            pass
