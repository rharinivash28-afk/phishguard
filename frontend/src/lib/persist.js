// Dual-layer persistence: a localStorage mirror of connection + last-known state so
// a page reload paints instantly (and survives a backend cold-start). Postgres via
// the API is always the source of truth — this is a cache we reconcile against.

const KEY = 'phishguard.v1';

const EMPTY = {
  connected: false,
  email: '',
  durationHours: 24, // last picked duration; null === Permanent
  connectedAt: null,
  expiresAt: null, // ISO string or null (Permanent / not connected)
  lastStats: null,
  lastInboxCount: 0,
  updatedAt: 0,
};

export function loadCache() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...EMPTY };
    const parsed = JSON.parse(raw);
    return { ...EMPTY, ...parsed };
  } catch {
    return { ...EMPTY };
  }
}

export function saveCache(partial) {
  try {
    const next = { ...loadCache(), ...partial, updatedAt: Date.now() };
    localStorage.setItem(KEY, JSON.stringify(next));
    return next;
  } catch {
    return null;
  }
}

export function clearConnection() {
  saveCache({
    connected: false,
    email: '',
    connectedAt: null,
    expiresAt: null,
    lastStats: null,
    lastInboxCount: 0,
  });
}
