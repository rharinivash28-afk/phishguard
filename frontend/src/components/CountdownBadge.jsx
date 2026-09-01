import React, { useEffect, useState } from 'react';
import { Clock, Infinity as InfinityIcon } from 'lucide-react';

// High-precision 1s countdown. Recomputes from Date.now() every tick so it never
// drifts; `expiresAt` (ms epoch, or null for Permanent) is refreshed by the parent
// from /api/gmail/status every ~10s and this badge interpolates between.
function fmt(msLeft) {
  if (msLeft <= 0) return '00:00:00';
  const s = Math.floor(msLeft / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n) => String(n).padStart(2, '0');
  if (d > 0) return `${d}d ${pad(h)}:${pad(m)}`;
  return `${pad(h)}:${pad(m)}:${pad(sec)}`;
}

export default function CountdownBadge({ expiresAt, permanent, onClick }) {
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (permanent) return undefined;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [permanent]);

  if (permanent) {
    return (
      <button
        onClick={onClick}
        title="Gmail connection: Permanent (no expiry)"
        className="flex items-center gap-1.5 glass-soft px-2.5 py-1.5 font-mono text-xs text-white/85 hover:bg-white/[0.09] transition"
      >
        <InfinityIcon className="w-3.5 h-3.5 text-white/60" />
        <span className="font-semibold tracking-wide">PERMANENT</span>
      </button>
    );
  }

  const msLeft = expiresAt ? expiresAt - now : 0;
  const critical = msLeft > 0 && msLeft < 5 * 60 * 1000; // under 5 min
  const expired = msLeft <= 0;

  return (
    <button
      onClick={onClick}
      title="Time left on this Gmail connection — click to manage"
      className={`flex items-center gap-1.5 glass-soft px-2.5 py-1.5 font-mono text-xs transition hover:bg-white/[0.09] ${
        expired ? 'text-[#ff8585]' : critical ? 'text-[#ffcf5c]' : 'text-white/85'
      }`}
    >
      <Clock className={`w-3.5 h-3.5 ${critical || expired ? '' : 'text-white/60'} ${critical ? 'animate-pulse' : ''}`} />
      <span className="font-semibold tracking-wider tabular-nums">
        {expired ? 'EXPIRED' : fmt(msLeft)}
      </span>
    </button>
  );
}
