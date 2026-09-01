import React, { useEffect, useRef, useState } from 'react';
import { Check, X, Loader2 } from 'lucide-react';

const STEPS = ['Validating credentials', 'TLS/SSL handshake', 'Mailbox indexing'];

// Animated 3-step connect bar. While the POST is in flight it advances on an
// optimistic timer; when `phases` (the real per-step result from the backend)
// arrives it snaps each step to its true ok/ms. `error` marks the current step failed.
export default function ConnectProgress({ active, phases, error, done }) {
  const [optimStep, setOptimStep] = useState(0);
  const timer = useRef(null);

  useEffect(() => {
    if (!active) {
      setOptimStep(0);
      return undefined;
    }
    setOptimStep(0);
    let i = 0;
    timer.current = setInterval(() => {
      i = Math.min(i + 1, STEPS.length - 1);
      setOptimStep(i);
      if (i >= STEPS.length - 1) clearInterval(timer.current);
    }, 700);
    return () => clearInterval(timer.current);
  }, [active]);

  const realPhases = Array.isArray(phases) ? phases : [];
  const failedIdx = error ? Math.max(realPhases.length, optimStep) : -1;

  return (
    <div className="glass-soft p-4 space-y-2.5">
      {STEPS.map((label, i) => {
        const real = realPhases[i];
        let state = 'pending';
        if (real) state = real.ok ? 'ok' : 'fail';
        else if (i === failedIdx) state = 'fail';
        else if (done && !error) state = 'ok';
        else if (i < optimStep || (active && i === optimStep)) state = i === optimStep && !done ? 'running' : 'ok';

        return (
          <div key={label} className="flex items-center gap-3">
            <div
              className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 border ${
                state === 'ok'
                  ? 'bg-white text-black border-white'
                  : state === 'fail'
                  ? 'bg-[rgba(255,92,92,0.9)] text-black border-[rgba(255,92,92,0.9)]'
                  : state === 'running'
                  ? 'bg-white/[0.08] text-white border-white/30'
                  : 'bg-white/[0.04] text-white/30 border-white/12'
              }`}
            >
              {state === 'ok' && <Check className="w-3.5 h-3.5" />}
              {state === 'fail' && <X className="w-3.5 h-3.5" />}
              {state === 'running' && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              {state === 'pending' && <span className="text-[10px] font-mono">{i + 1}</span>}
            </div>
            <div className="flex-1 flex items-center justify-between">
              <span
                className={`text-xs font-medium ${
                  state === 'pending' ? 'text-white/40' : state === 'fail' ? 'text-[#ff8585]' : 'text-white/85'
                }`}
              >
                {label}
              </span>
              {real && (
                <span className="text-[10px] font-mono text-white/40">{real.ms} ms</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
