# Deploying PhishGuard (frontend + backend, one service)

The whole app ships as a single Docker image: the FastAPI backend serves the API
**and** the compiled React UI from the same origin. One URL, one deploy.

## How multi-user isolation works

Every visitor gets an opaque `pg_session` cookie on first load. That cookie **is**
their identity — no login. Each session is a private workspace: its own inbox,
quarantine, incident reports, and Gmail connection, all stored in Postgres keyed by
the session id. One session can never see another's mail. A "Wipe my data" button
deletes the session and everything under it; idle workspaces are swept after
`SESSION_TTL_DAYS` (default 14).

Gmail is connected with a **16-character app password** (read-only IMAP). The
password is encrypted at rest with `APP_SECRET_KEY` and only decrypted in-process
to run the poll. There is no Google OAuth — `gmail.readonly` OAuth needs app
verification (owned domain, privacy policy, security review) and caps unverified
apps at 100 users, so app-password is the only path.

## Prerequisites — a free Postgres database

Render's free web tier has no persistent disk, so per-user data lives in an
external Postgres. Both of these have a **permanent** free tier:

- **Neon** — https://neon.tech → new project → copy the connection string
  (`postgresql://user:pass@host/dbname`).
- **Supabase** — https://supabase.com → new project → Settings → Database →
  Connection string (URI).

Without `DATABASE_URL` the app falls back to an ephemeral SQLite file that is wiped
on every redeploy — fine for a quick look, not for real use.

## Option A — Render (recommended, free)

1. **Push this folder to a GitHub repo.**
   ```bash
   cd phishguard
   git init && git add . && git commit -m "PhishGuard"
   git branch -M main
   git remote add origin https://github.com/<you>/phishguard.git
   git push -u origin main
   ```

2. **Create the service.**
   - Render dashboard → **New +** → **Blueprint** → pick the repo.
   - Render reads `render.yaml`, builds the `Dockerfile`, starts one web service,
     and generates `APP_SECRET_KEY` for you.
   - It will **prompt for `DATABASE_URL`** — paste the Neon/Supabase string.
   - First build ~4–6 min → `https://phishguard-xxxx.onrender.com`.

3. **Use it.** Open the URL, click **Connect Gmail**, follow the in-app steps
   (enable 2-Step Verification → enable IMAP → generate an app password → paste).
   Every visitor does this for their own account.

### Notes
- Free tier sleeps after ~15 min idle (first request then takes ~30–50 s to wake).
  **Background Gmail polling is paused while asleep** — the inbox catches up on the
  next visit or "Scan now". A paid always-on instance removes this with no code
  change.
- Data survives redeploys because it's in Postgres, not on the dyno.
- `APP_SECRET_KEY` must stay stable — if it changes, stored app passwords can't be
  decrypted and users just reconnect.

## Option B — Fly.io (always-on, no sleep)

```bash
cd phishguard
fly launch --no-deploy          # accept the detected Dockerfile, pick a name/region
fly secrets set DATABASE_URL=postgresql://...  APP_SECRET_KEY=$(openssl rand -hex 32)
fly deploy
```
`fly.toml` internal_port must be `8000` (Fly injects `$PORT`).

## Option C — any Docker host / a VM

```bash
docker build -t phishguard .
docker run -p 8000:8000 \
  -e DATABASE_URL=postgresql://user:pass@host/db \
  -e APP_SECRET_KEY=$(openssl rand -hex 32) \
  phishguard
```

## Local development

No Postgres needed — `DATABASE_URL` unset uses `backend/phishguard.db` (SQLite).

```bash
cd backend && python run_tests.py       # all backend tests, no pytest needed
cd ../frontend && npm run build && cd ..
cd backend && python app.py             # serves API + built UI on :8000
```
Then open http://localhost:8000 (not 5173). For the hot-reload dev UI run
`npm run dev` in `frontend/` (proxies `/api` to :8000) and open :5173.

## Cloudflare?

Not supported without a rewrite. Cloudflare Workers can't run this Python process
or open the IMAP sockets the app-password login needs. A Workers port would be JS,
with D1 for state and a cron trigger replacing the polling loop.
