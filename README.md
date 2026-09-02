# PhishGuard AI — Enterprise Inbox Sentinel

**Zero-PII, offline-first phishing forensics with a private per-user workspace,
live Gmail monitoring, and law-enforcement-grade incident reporting.**

🔗 **Live:** https://phishguard-0aqn.onrender.com

---

## What it does

PhishGuard turns any suspicious email into a full forensic verdict in under a second —
**with no email content ever leaving the deterministic engine.** It runs three ways:

1. **Live Gmail Sentinel** — connect a Gmail with a read-only app password, pick a
   session duration (1h / 4h / 12h / 24h / Permanent), and PhishGuard scans your inbox
   every minute, auto-quarantining phishing and building an incident dossier for each hit.
2. **Deep Forensics workbench** — paste any email's headers and body (or one of three
   quick-fill presets) and get a multi-factor risk breakdown, every fired indicator
   explained, and a **STIX 2.1 threat-intelligence bundle**.
3. **`.eml` / paste inspector** — drop a saved `.eml` file or paste raw email details;
   no Gmail connection needed.

---

## The 4-tier hybrid detection engine

Every verdict is a weighted composite of four deterministic analyzers plus an optional
LLM second opinion. **No email text is sent anywhere** — the core engine is pure Python
with zero network dependency.

| Tier | Analyzer | Sample indicators |
| --- | --- | --- |
| **1 — Sender & domain** | SPF / DKIM / DMARC parser, homoglyph fold, length-scaled brand typosquatting (Levenshtein + one-directional homoglyph normalization over ~75 brands) | `BRAND_TYPOSQUATTING_HOMOGLYPH`, `DISPLAY_NAME_SPOOFING`, `SPF_VALIDATION_FAILED`, `DMARC_POLICY_REJECT` |
| **2 — URL inspection** | scheme downgrade, raw-IP hosts, credential-harvesting paths, suspicious TLDs, deceptive subdomains, anchor-text ≠ href mismatch | `INSECURE_PROTOCOL`, `RAW_IP_URL`, `ANCHOR_TEXT_MISMATCH`, `SUSPICIOUS_TLD`, `CREDENTIAL_HARVESTING_PATH` |
| **3 — NLP urgency & coercion** | urgency / threat / scarcity / authority phrasing classifier | `URGENCY_NLP_TRIGGER` |
| **4 — Attachments** | double-extension payloads, macro-enabled & executable types, **real SHA-256 of the payload bytes** | `DOUBLE_EXTENSION_PAYLOAD`, `MALICIOUS_ATTACHMENT_TYPE` |
| *Optional* | Google Safe Browsing v4 URL reputation · NVIDIA-hosted Llama 3.1 70B second opinion (borderline scores only) | `SAFE_BROWSING_BLOCKLIST`, `AI_MODEL_FLAGGED` |

HTML email bodies are fully parsed (BeautifulSoup) so `<a href>` / anchor-text mismatch
detection works on real mail, not just plaintext.

---

## Privacy & isolation architecture

- **Zero-PII forensics** — the scoring engine never makes a network call. Email content
  stays local to the process.
- **Strict per-session isolation** — every visitor gets an opaque `pg_session` cookie
  that *is* their identity (no login). Inbox, quarantine, incident reports and the Gmail
  connection all hang off that session id in Postgres; one session can never see
  another's mail. "Wipe my data" deletes the session and everything under it.
- **Dual-layer persistence** — Postgres (Neon) is the source of truth; the browser keeps
  a `localStorage` mirror of connection state + last-known metrics + chosen duration so a
  reload repaints instantly and survives a backend cold start.
- **Credentials** — the 16-character Gmail app password is Fernet-encrypted at rest
  (`APP_SECRET_KEY`), decrypted only in-process to run a poll, and wiped on disconnect.
- **Unshakeable connection** — a transient network error (timeout, DNS blip, TLS reset)
  never drops a live connection; only a real credential rejection, or five consecutive
  transient failures, does.
- **Connection duration** — enforced server-side on every poll *and* by the background
  poller, so an expired connection is torn down even with the browser closed. A
  1-second high-precision countdown badge shows the time left.

---

## Incident reporting

Every quarantined email produces a **Cybercrime Incident Dossier**:

- Executive summary — classification verdict, impersonated brand, composite risk score,
  automated action
- **Indicators of Compromise** — malicious domains, phishing URLs, artifact SHA-256 hashes
- **MITRE ATT&CK tactical mapping** (`T1566.002`, `T1036.007`, `T1204.001`, …)
- Mandatory containment & remediation playbook
- Exports: Markdown dossier · **STIX 2.1 bundle** (`identity`, `indicator` objects with
  STIX patterns, `observed-data` + email/file SCOs with real hashes, `attack-pattern`
  refs, `indicates` relationships — deterministic uuid5 ids) · print

---

## Tech stack

| Layer | Choice |
| --- | --- |
| Backend | FastAPI · SQLAlchemy 2 · Alembic migrations · slowapi rate limiting |
| Database | Postgres (Neon free tier) — SQLite fallback for local dev |
| Frontend | React 18 · Vite · Tailwind (glassmorphism black-&-white theme) |
| Gmail | read-only IMAP over TLS with a Google App Password (no OAuth — see below) |
| Deploy | single multi-stage Docker image on Render free tier; one URL serves API + UI |
| Polling | in-process daemon thread + external cron (`/api/cron/poll-tick`) to survive free-tier sleep |
| Tests | 40 zero-dependency backend tests (`python backend/run_tests.py`) |

### Why app-password, not "Sign in with Google"

Reading a user's Gmail requires the `gmail.readonly` **restricted** OAuth scope, which
Google gates behind app verification: a published privacy policy on an owned domain, a
CASA security assessment, and a 4–8 week review, with unverified apps capped at 100 users
behind a warning screen. App-password IMAP gives the same read-only access with no
verification barrier and is the pragmatic choice for this build. Google OAuth is a
documented post-hackathon step.

---

## Run it locally

No Postgres needed — `DATABASE_URL` unset uses a local SQLite file.

```bash
# backend tests (no pytest required)
cd backend && python run_tests.py

# build the UI and serve everything on :8000
cd ../frontend && npm install && npm run build && cd ..
cd backend && pip install -r requirements.txt
DATABASE_URL="sqlite:///./dev.db" python app.py
# open http://localhost:8000
```

For the hot-reload dev UI: `npm run dev` in `frontend/` (proxies `/api` to :8000),
open `:5173`.

Full deployment guide — Render, Fly, plain Docker, the cron job, optional API keys —
in [DEPLOY.md](DEPLOY.md).

---

## Repository layout

```
backend/
  analyzer.py           4-tier deterministic engine
  stix_builder.py       STIX 2.1 bundle generation
  report_generator.py   cybercrime incident dossier
  gmail_service.py       IMAP + HTML/.eml parsing, transient-vs-auth error split
  user_workspace.py     per-session state (inbox, quarantine, Gmail, duration)
  session_store.py      cookie identity + TTL sweep
  poller.py             background scan loop + cron tick
  threat_intel.py       Google Safe Browsing (optional)
  llm_review.py         NVIDIA Llama 3.1 70B second opinion (optional)
  crypto.py             Fernet encryption for app passwords
  migrations/           Alembic
  test_*.py             40 tests
frontend/src/
  components/            LiveSentinel, DeepInvestigator, IncidentReports,
                         3 modals + shared Modal shell, CountdownBadge, ConnectProgress
  lib/persist.js         localStorage mirror
```
