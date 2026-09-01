import base64
import json
import os
import re
import threading
import time
import urllib.parse
import uuid
import requests
from typing import Dict, Any, List, Optional
from analyzer import PhishingInvestigationEngine
from report_generator import CybercrimeIncidentReportGenerator

ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")


def _persist_env(updates: Dict[str, str]) -> None:
    """Merge key=value pairs into backend/.env so credentials survive a restart."""
    data: Dict[str, str] = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
    data.update({k: v for k, v in updates.items() if v is not None})
    with open(ENV_PATH, "w", encoding="utf-8") as fh:
        fh.write("# PhishGuard local secrets — auto-managed. Do not commit.\n")
        for k, v in data.items():
            fh.write(f"{k}={v}\n")
    for k, v in updates.items():
        if v is not None:
            os.environ[k] = v


class GmailOAuthService:
    def __init__(self, engine: PhishingInvestigationEngine, sentinel_manager):
        self.engine = engine
        self.sentinel = sentinel_manager

        # OAuth Configuration.
        # "Shared client" mode: when the operator provides GOOGLE_CLIENT_ID/SECRET as
        # environment variables (baked into the deployment), every visitor gets a pure
        # one-click "Sign in with Google" - no per-user setup. The in-app credential
        # form is only for local tinkering and is hidden once env creds are present.
        self.client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
        self.client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
        self.shared_client = bool(self.client_id and self.client_secret)
        # Redirect URI priority:
        #   1. explicit GOOGLE_REDIRECT_URI
        #   2. PUBLIC_BASE_URL / RENDER_EXTERNAL_URL + the callback path (prod, single origin)
        #   3. local dev: through the Vite proxy
        _base = (
            os.environ.get("PUBLIC_BASE_URL")
            or os.environ.get("RENDER_EXTERNAL_URL")
            or ""
        ).rstrip("/")
        self.redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI") or (
            f"{_base}/api/auth/google/callback" if _base
            else "http://localhost:5173/api/auth/google/callback"
        )

        self.tokens = {
            "access_token": "",
            "refresh_token": os.environ.get("GOOGLE_REFRESH_TOKEN", ""),
            "expires_at": 0,
            "user_email": os.environ.get("GOOGLE_USER_EMAIL", ""),
            "user_name": "",
            "user_picture": "",
            "is_connected": False,
        }

        self.seen_gmail_ids = set()
        self.is_oauth_sync_active = False
        self.sync_thread = None
        self._lock = threading.RLock()

        # If we already have a refresh token from a previous session, reconnect silently.
        if self.tokens["refresh_token"] and self.client_id and self.client_secret:
            try:
                if self.refresh_access_token().get("status") == "SUCCESS":
                    self.tokens["is_connected"] = True
                    self.is_oauth_sync_active = True
                    self.sentinel.gmail_credentials["email"] = self.tokens["user_email"]
                    self.sentinel.gmail_credentials["connected"] = True
                    self.sentinel.monitoring_mode = "GMAIL_OAUTH_API"
                    self._start_oauth_sync_daemon()
            except Exception as exc:  # pragma: no cover - best effort
                print(f"[OAuth silent reconnect] {exc}")

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------
    def save_client_credentials(self, client_id: str, client_secret: str) -> Dict[str, Any]:
        if self.shared_client:
            return {
                "status": "ERROR",
                "error": "This deployment already has a shared Google client configured - "
                         "just click 'Sign in with Google'.",
            }
        client_id = (client_id or "").strip()
        client_secret = (client_secret or "").strip()
        if not client_id or not client_secret:
            return {"status": "ERROR", "error": "Both Client ID and Client Secret are required."}

        # Guard against the most common mix-up: pasting a Gmail address / app password
        # (which belong in the App-password tab) into the OAuth client fields.
        if "@" in client_id or ".apps.googleusercontent.com" not in client_id:
            return {
                "status": "ERROR",
                "error": "That doesn't look like an OAuth Client ID. It should end in "
                         "'.apps.googleusercontent.com' (from Google Cloud -> Credentials). "
                         "If you have a 16-character Gmail App Password, use the 'App password' tab instead.",
            }
        if re.fullmatch(r"[a-z]{4}(\s?[a-z]{4}){3}", client_secret, flags=re.I):
            return {
                "status": "ERROR",
                "error": "That looks like a Gmail App Password, not an OAuth Client Secret. "
                         "Use the 'App password' tab for that. The Client Secret starts with 'GOCSPX-'.",
            }

        with self._lock:
            self.client_id = client_id
            self.client_secret = client_secret
        _persist_env({"GOOGLE_CLIENT_ID": client_id, "GOOGLE_CLIENT_SECRET": client_secret})
        return {"status": "SUCCESS", "redirect_uri": self.redirect_uri}

    def has_client_credentials(self) -> bool:
        return bool(self.client_id and self.client_secret)

    # ------------------------------------------------------------------
    # OAuth 2.0 Authorization-Code flow
    # ------------------------------------------------------------------
    def get_auth_url(self) -> str:
        if not self.client_id:
            return ""
        scopes = [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ]
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "access_type": "offline",
            "include_granted_scopes": "true",
            # let the user pick / switch the Google account, and still grant a refresh token
            "prompt": "select_account consent",
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"

    def exchange_code_for_tokens(self, code: str) -> Dict[str, Any]:
        payload = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        resp = requests.post("https://oauth2.googleapis.com/token", data=payload, timeout=15)
        if resp.status_code != 200:
            return {"status": "ERROR", "error": resp.text}

        data = resp.json()
        access_token = data.get("access_token", "")
        refresh_token = data.get("refresh_token", "")
        expires_in = data.get("expires_in", 3600)

        userinfo = {}
        try:
            ui = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            if ui.status_code == 200:
                userinfo = ui.json()
        except Exception:
            pass

        new_email = userinfo.get("email", "connected.user@gmail.com")
        account_changed = bool(self.tokens.get("user_email")) and self.tokens["user_email"] != new_email

        with self._lock:
            # A different Google account signed in -> forget the old inbox entirely.
            self.seen_gmail_ids.clear()
            self.tokens["access_token"] = access_token
            # refresh tokens are per-account; drop the old one unless Google re-issued
            self.tokens["refresh_token"] = refresh_token or ("" if account_changed else self.tokens.get("refresh_token", ""))
            self.tokens["expires_at"] = time.time() + expires_in
            self.tokens["user_email"] = new_email
            self.tokens["user_name"] = userinfo.get("name", new_email.split("@")[0])
            self.tokens["user_picture"] = userinfo.get("picture", "")
            self.tokens["is_connected"] = True
            self.is_oauth_sync_active = True
            self.sentinel.monitoring_mode = "GMAIL_OAUTH_API"

        # wipe any previous user's mail / reports / quarantine
        self.sentinel.reset_for_account(new_email)
        self.sentinel.gmail_credentials["connected"] = True

        _persist_env(
            {
                "GOOGLE_REFRESH_TOKEN": self.tokens["refresh_token"],
                "GOOGLE_USER_EMAIL": self.tokens["user_email"],
            }
        )

        self._start_oauth_sync_daemon()
        self.fetch_latest_messages_now()
        return {
            "status": "SUCCESS",
            "email": self.tokens["user_email"],
            "name": self.tokens["user_name"],
        }

    def refresh_access_token(self) -> Dict[str, Any]:
        refresh_token = self.tokens.get("refresh_token")
        if not refresh_token or not self.client_id or not self.client_secret:
            return {"status": "NO_REFRESH_TOKEN"}
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        resp = requests.post("https://oauth2.googleapis.com/token", data=payload, timeout=15)
        if resp.status_code != 200:
            return {"status": "ERROR", "error": resp.text}
        data = resp.json()
        with self._lock:
            self.tokens["access_token"] = data.get("access_token", "")
            self.tokens["expires_at"] = time.time() + data.get("expires_in", 3600)
            self.tokens["is_connected"] = True
            if not self.tokens.get("user_name"):
                self.tokens["user_name"] = (self.tokens.get("user_email") or "gmail").split("@")[0]
        return {"status": "SUCCESS"}

    def _ensure_fresh_token(self) -> None:
        if self.tokens.get("refresh_token") and time.time() > self.tokens.get("expires_at", 0) - 120:
            self.refresh_access_token()

    # ------------------------------------------------------------------
    # Legacy: paste-an-access-token path (still supported)
    # ------------------------------------------------------------------
    def connect_with_direct_token(self, email_address: str, access_token: str) -> Dict[str, Any]:
        with self._lock:
            self.seen_gmail_ids.clear()
            self.tokens["access_token"] = access_token
            self.tokens["refresh_token"] = ""
            self.tokens["user_email"] = email_address
            self.tokens["user_name"] = email_address.split("@")[0]
            self.tokens["is_connected"] = True
            self.tokens["expires_at"] = time.time() + 3600
            self.is_oauth_sync_active = True
            self.sentinel.monitoring_mode = "GMAIL_OAUTH_API"

        self.sentinel.reset_for_account(email_address)
        self.sentinel.gmail_credentials["connected"] = True

        self._start_oauth_sync_daemon()
        sync_res = self.fetch_latest_messages_now()
        return {"status": "SUCCESS", "email": email_address, "sync_result": sync_res}

    def disconnect(self):
        with self._lock:
            self.tokens["access_token"] = ""
            self.tokens["refresh_token"] = ""
            self.tokens["user_email"] = ""
            self.tokens["user_name"] = ""
            self.tokens["user_picture"] = ""
            self.tokens["is_connected"] = False
            self.tokens["expires_at"] = 0
            self.is_oauth_sync_active = False
            self.seen_gmail_ids.clear()
            self.sentinel.monitoring_mode = "ACTIVE_SENTINEL"
        # back to the demo inbox so the app isn't empty
        self.sentinel.reset_for_account("", keep_samples=True)
        self.sentinel.gmail_credentials["email"] = "harinivash28082007@gmail.com"
        self.sentinel.gmail_credentials["connected"] = False
        self.sentinel.gmail_credentials["imap_connected"] = False
        self.sentinel.gmail_credentials["app_password"] = ""
        _persist_env({"GOOGLE_REFRESH_TOKEN": "", "GOOGLE_USER_EMAIL": ""})
        return {"status": "DISCONNECTED"}

    # ------------------------------------------------------------------
    # Sync daemon
    # ------------------------------------------------------------------
    def _start_oauth_sync_daemon(self):
        if self.sync_thread and self.sync_thread.is_alive():
            return
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()

    def _sync_loop(self):
        while True:
            try:
                if self.is_oauth_sync_active and (self.tokens.get("access_token") or self.tokens.get("refresh_token")):
                    self._ensure_fresh_token()
                    self.fetch_latest_messages_now()
                time.sleep(15)
            except Exception as e:
                print(f"[OAuth Gmail Sync Daemon]: {e}")
                time.sleep(15)

    def fetch_latest_messages_now(self, max_results: int = 15) -> Dict[str, Any]:
        self._ensure_fresh_token()
        token = self.tokens.get("access_token")
        if not token:
            return {"status": "NOT_CONNECTED", "count": 0}

        headers = {"Authorization": f"Bearer {token}"}
        url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults={max_results}&q=in:inbox"

        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 401:
                if self.refresh_access_token().get("status") == "SUCCESS":
                    headers = {"Authorization": f"Bearer {self.tokens['access_token']}"}
                    resp = requests.get(url, headers=headers, timeout=15)
                else:
                    self.tokens["is_connected"] = False
                    return {"status": "TOKEN_EXPIRED", "error": "Access token expired. Please re-authenticate."}

            if resp.status_code != 200:
                return {"status": "API_ERROR", "error": resp.text}

            data = resp.json()
            messages = data.get("messages", [])
            new_emails_processed = 0

            for msg_item in messages:
                msg_id = msg_item.get("id")
                if not msg_id or msg_id in self.seen_gmail_ids:
                    continue

                self.seen_gmail_ids.add(msg_id)
                detail_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full"
                detail_resp = requests.get(detail_url, headers=headers, timeout=15)

                if detail_resp.status_code == 200:
                    parsed = self._parse_gmail_api_message(detail_resp.json())
                    self.sentinel.process_new_email(parsed)
                    new_emails_processed += 1

            return {"status": "SUCCESS", "new_emails_count": new_emails_processed, "total_scanned": len(messages)}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def _parse_gmail_api_message(self, msg_detail: Dict[str, Any]) -> Dict[str, Any]:
        msg_id = msg_detail.get("id", str(uuid.uuid4().hex[:8]))
        payload = msg_detail.get("payload", {})
        headers_list = payload.get("headers", [])

        headers_dict = {h.get("name", "").lower(): h.get("value", "") for h in headers_list}

        subject = headers_dict.get("subject", "No Subject")
        sender = headers_dict.get("from", "Unknown Sender")
        date_str = headers_dict.get("date", time.strftime("%Y-%m-%d %H:%M"))

        display_name = sender.split("<")[0].strip().replace('"', '') if "<" in sender else sender
        clean_sender = sender.split("<")[-1].strip(">").strip() if "<" in sender else sender

        body_text = self._extract_body_from_payload(payload) or msg_detail.get("snippet", "")

        auth_results = headers_dict.get("authentication-results", "").lower()
        received_spf = headers_dict.get("received-spf", "").lower()

        spf_status = "PASS" if ("spf=pass" in auth_results or "pass" in received_spf) else ("FAIL" if "spf=fail" in auth_results else "UNKNOWN")
        dkim_status = "PASS" if "dkim=pass" in auth_results else ("FAIL" if "dkim=fail" in auth_results else "UNKNOWN")
        dmarc_status = "PASS" if "dmarc=pass" in auth_results else ("FAIL" if "dmarc=fail" in auth_results else "UNKNOWN")

        gmail_web_url = f"https://mail.google.com/mail/u/0/#inbox/{msg_id}"

        extracted_urls = re.findall(r'https?://[^\s<>"\'\)]+', body_text)
        urls = [{"url": u, "anchor": ""} for u in extracted_urls]

        return {
            "id": f"gmail_api_{msg_id}",
            "title": f"Gmail: {subject[:30]}",
            "sender_address": clean_sender,
            "display_name": display_name,
            "subject": subject,
            "recipient": self.tokens.get("user_email", "user@gmail.com"),
            "date": date_str,
            "body": body_text,
            "urls": urls,
            "attachments": [],
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "gmail_web_url": gmail_web_url,
            "message_id": msg_id,
        }

    def _extract_body_from_payload(self, payload: Dict[str, Any]) -> str:
        body_data = payload.get("body", {}).get("data")
        if body_data:
            try:
                return base64.urlsafe_b64decode(body_data).decode("utf-8", errors="ignore")
            except Exception:
                pass

        parts = payload.get("parts", [])
        for part in parts:
            mime_type = part.get("mimeType", "")
            data = part.get("body", {}).get("data")
            if mime_type == "text/plain" and data:
                try:
                    return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                except Exception:
                    pass
            elif part.get("parts"):
                nested = self._extract_body_from_payload(part)
                if nested:
                    return nested
        return ""

    def get_oauth_status(self) -> Dict[str, Any]:
        return {
            "is_connected": self.tokens.get("is_connected", False),
            "user_email": self.tokens.get("user_email", ""),
            "user_name": self.tokens.get("user_name", ""),
            "user_picture": self.tokens.get("user_picture", ""),
            "client_id_configured": self.has_client_credentials(),
            "shared_client": self.shared_client,
            "redirect_uri": self.redirect_uri,
            "expires_in_seconds": max(int(self.tokens.get("expires_at", 0) - time.time()), 0),
        }
