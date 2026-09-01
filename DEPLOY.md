# Deploying PhishGuard (frontend + backend, one service)

The whole app ships as a single Docker image: the FastAPI backend serves the API
**and** the compiled React UI from the same origin. One URL, one deploy.

## Option A — Render (recommended, free)

1. **Push this folder to a GitHub repo.**
   ```bash
   cd "phishguard"
   git init && git add . && git commit -m "PhishGuard"
   git branch -M main
   git remote add origin https://github.com/<you>/phishguard.git
   git push -u origin main
   ```

2. **Create the service.**
   - Render dashboard → **New +** → **Blueprint** → pick the repo.
   - Render reads `render.yaml`, builds the `Dockerfile`, and starts one web service.
   - First build ~4–6 min. You get `https://phishguard-xxxx.onrender.com`.

3. **Wire up Google sign-in** (only if you want live Gmail):
   - [Google Cloud Console](https://console.cloud.google.com/) → new project.
   - **APIs & Services → Library** → enable **Gmail API**.
   - **OAuth consent screen** → External → add your Gmail as a **Test user**.
   - **Credentials → Create credentials → OAuth client ID → Web application**.
     Authorized redirect URI:
     ```
     https://phishguard-xxxx.onrender.com/api/auth/google/callback
     ```
   - Open the app → **Connect Gmail → Google sign-in → One-time setup** → paste
     Client ID + Secret → **Save** → **Sign in with Google**.
   - (Or set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` as env vars in Render and
     skip the in-app step.)

   The refresh token is saved to `backend/.env` inside the container. Render's disk
   is ephemeral, so after a redeploy you sign in once more — or add a Render
   **Persistent Disk** mounted at `/app/backend` to keep it.

### Notes
- Free tier sleeps after 15 min idle (first request then takes ~30 s to wake).
  That also pauses the background Gmail polling while asleep.
- App-password / IMAP login works here too (unlike Cloudflare Workers).

## Option B — Fly.io (always-on, no sleep)

```bash
cd "phishguard"
fly launch --no-deploy          # accept the detected Dockerfile, pick a name/region
fly deploy
```
Set the redirect URI to `https://<app>.fly.dev/api/auth/google/callback`.
`fly.toml` internal_port must be `8000` (Fly injects `$PORT`).

## Option C — any Docker host / a VM

```bash
docker build -t phishguard .
docker run -p 8000:8000 \
  -e PUBLIC_BASE_URL=https://your-domain.com \
  -e GOOGLE_CLIENT_ID=... -e GOOGLE_CLIENT_SECRET=... \
  phishguard
```

## Local production check

```bash
cd backend && python test_analyzer.py   # analyzer regression tests, no deps
cd ../frontend && npm run build && cd ..
cd backend && python app.py              # detects ../frontend/dist and serves everything on :8000
```
Then open http://localhost:8000 (not 5173).

## Cloudflare?

Not supported without a rewrite. Cloudflare Workers can't run this Python process,
can't hold in-memory state, and can't open the IMAP sockets the app-password login
needs. A Workers port would be OAuth-only, JS, with D1/KV for state and a cron
trigger replacing the polling loop.
