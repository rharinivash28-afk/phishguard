# ---------- Stage 1: build the React frontend ----------
FROM node:20-bullseye-slim AS frontend
WORKDIR /build

# install deps first so this layer caches independently of source changes
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
# Vite/rollup can spike past the default heap on small build boxes.
ENV NODE_OPTIONS=--max-old-space-size=2048
RUN npm run build          # -> /build/dist

# ---------- Stage 2: Python API that also serves the built frontend ----------
FROM python:3.11-slim-bullseye AS runtime
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY --from=frontend /build/dist ./frontend/dist

WORKDIR /app/backend
EXPOSE 8000
# Render / Fly inject $PORT; default to 8000 locally.
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
