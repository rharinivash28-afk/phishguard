import React, { useState } from 'react';
import { X, Mail, Key, Check, RefreshCw, AlertCircle, ExternalLink, Eye, EyeOff, LogOut, ShieldCheck, Clock } from 'lucide-react';
import ConnectProgress from './ConnectProgress';
import Modal from './Modal';

const DURATION_LABELS = { 1: '1 hour', 4: '4 hours', 12: '12 hours', 24: '24 hours' };
const durationLabel = (h) => (h === null || h === undefined ? 'Permanent' : DURATION_LABELS[h] || `${h} hours`);

export default function GmailSettingsModal({
  stats,
  connection,
  config,
  defaultDuration,
  onClose,
  onConnectGmail,
  onDisconnectGmail,
  onToggleMonitoring,
  onTriggerScan,
}) {
  const connected = connection?.connected || stats?.connected || stats?.imap_connected;
  const connectedEmail = connection?.email || stats?.connected_email || '';

  const durations = config?.durations ?? [1, 4, 12, 24, null];
  const initialDuration =
    defaultDuration !== undefined ? defaultDuration : (config?.default_duration_hours ?? 24);

  const [email, setEmail] = useState(connectedEmail);
  const [appPassword, setAppPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [duration, setDuration] = useState(initialDuration);
  const [active, setActive] = useState(stats?.monitoring_active ?? true);
  const [busy, setBusy] = useState(false);
  const [phases, setPhases] = useState(null);
  const [connectError, setConnectError] = useState(null);
  const [connectDone, setConnectDone] = useState(false);
  const [msg, setMsg] = useState(null);
  const [scanning, setScanning] = useState(false);

  const pwLen = appPassword.replace(/\s+/g, '').length;

  const handleConnect = async (e) => {
    e.preventDefault();
    if (!email || !appPassword) return;
    setBusy(true);
    setMsg(null);
    setPhases(null);
    setConnectError(null);
    setConnectDone(false);

    const durVal = duration === 'null' ? null : duration;
    const res = await onConnectGmail(email.trim(), appPassword, durVal);

    setBusy(false);
    setPhases(res?.phases || []);
    if (res?.connected) {
      setConnectDone(true);
      setMsg({
        ok: true,
        text: res.note
          ? res.note
          : `Connected — ${res.new_emails_found ?? 0} recent messages pulled in. Session: ${durationLabel(durVal)}.`,
      });
      setAppPassword('');
      setTimeout(() => onClose(), 1400);
    } else {
      setConnectError(res?.error || 'Gmail rejected the login.');
      setMsg({ ok: false, text: res?.error || 'Gmail rejected the login. Check the steps below and retry.' });
    }
  };

  const handleDisconnect = async () => {
    setBusy(true);
    await onDisconnectGmail();
    setBusy(false);
    setMsg(null);
    setEmail('');
  };

  const handleScan = async () => {
    setScanning(true);
    await onTriggerScan?.();
    setScanning(false);
  };

  const toggleActive = async () => {
    const next = !active;
    setActive(next);
    await onToggleMonitoring?.(next);
  };

  return (
    <Modal onClose={onClose} maxWidth="max-w-lg">
        <div className="p-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-white text-black flex items-center justify-center"><Mail className="w-5 h-5" /></div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white">Connect your Gmail</h3>
                <span className={`px-2 py-0.5 text-[9px] font-bold uppercase rounded-full border ${
                  connected ? 'bg-white text-black border-white' : 'bg-white/[0.06] text-white/50 border-white/15'
                }`}>
                  {connected ? 'Connected' : 'Not connected'}
                </span>
              </div>
              <p className="text-xs text-white/45">Read-only IMAP with a 16-character app password.</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 text-white/40 hover:text-white rounded-lg transition"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-6 space-y-4 text-xs">
          {connected && (
            <div className="glass-soft p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-white text-black flex items-center justify-center font-bold uppercase">
                    {(connectedEmail || 'G')[0]}
                  </div>
                  <div>
                    <p className="font-bold text-white text-xs">Gmail — IMAP app password</p>
                    <p className="text-[11px] text-white/50 font-mono">{connectedEmail}</p>
                  </div>
                </div>
                <button onClick={handleDisconnect} disabled={busy} title="Disconnect & clear synced mail"
                  className="p-2 rounded-xl bg-white/[0.06] border border-white/12 text-white/50 hover:text-white hover:bg-white/[0.12] transition">
                  <LogOut className="w-4 h-4" />
                </button>
              </div>

              {connection?.expires_at || connection?.permanent ? (
                <div className="flex items-center gap-2 text-[11px] text-white/55 pt-2 border-t border-white/10">
                  <Clock className="w-3.5 h-3.5 text-white/40" />
                  <span>
                    Session duration: <span className="text-white/80 font-semibold">
                      {connection.permanent ? 'Permanent' : durationLabel(connection.duration_hours)}
                    </span>
                    {connection.expires_at && !connection.permanent && (
                      <> · expires {new Date(connection.expires_at).toLocaleString()}</>
                    )}
                  </span>
                </div>
              ) : null}

              <div className="flex items-center justify-between pt-3 border-t border-white/10">
                <div>
                  <p className="font-bold text-white text-xs flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full ${active ? 'bg-white animate-pulse' : 'bg-white/30'}`} />
                    24/7 background monitoring
                  </p>
                  <p className="text-[11px] text-white/45 mt-0.5">Scans your inbox every minute and auto-quarantines phishing.</p>
                </div>
                <button type="button" onClick={toggleActive}
                  className={`w-12 h-6 flex items-center rounded-full p-1 transition ${active ? 'bg-white justify-end' : 'bg-white/15 justify-start'}`}>
                  <div className={`w-4 h-4 rounded-full ${active ? 'bg-black' : 'bg-white/70'}`} />
                </button>
              </div>

              <button type="button" onClick={handleScan} disabled={scanning} className="btn-ghost w-full">
                <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
                <span>{scanning ? 'Scanning…' : 'Scan now'}</span>
              </button>
            </div>
          )}

          {!connected && (
            <form onSubmit={handleConnect} className="space-y-3">
              <p className="text-[11px] text-white/50 leading-relaxed">
                Enable IMAP in Gmail, generate a 16-character App Password (needs 2-Step Verification), and paste it here.
                PhishGuard never sees your real password and only reads your mail.
              </p>

              <div>
                <label className="block text-[10px] font-semibold uppercase text-white/45 mb-1">Gmail address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-white/35 absolute left-3 top-2.5" />
                  <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@gmail.com" className="glass-input pl-9" />
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-semibold uppercase text-white/45 mb-1">16-character App Password</label>
                <div className="relative">
                  <Key className="w-4 h-4 text-white/35 absolute left-3 top-2.5" />
                  <input type={showPw ? 'text' : 'password'} required value={appPassword}
                    onChange={(e) => setAppPassword(e.target.value)}
                    placeholder="abcd efgh ijkl mnop" className="glass-input pl-9 pr-10 font-mono" />
                  <button type="button" onClick={() => setShowPw((v) => !v)}
                    className="absolute right-2.5 top-2 p-0.5 text-white/40 hover:text-white transition">
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {appPassword && <p className="mt-1 text-[10px] text-white/40 font-mono">{pwLen} / 16 characters</p>}
              </div>

              <div>
                <label className="block text-[10px] font-semibold uppercase text-white/45 mb-1">Connection duration</label>
                <div className="relative">
                  <Clock className="w-4 h-4 text-white/35 absolute left-3 top-2.5" />
                  <select
                    value={duration === null ? 'null' : duration}
                    onChange={(e) => setDuration(e.target.value === 'null' ? null : Number(e.target.value))}
                    className="glass-input pl-9 appearance-none"
                  >
                    {durations.map((d) => (
                      <option key={d === null ? 'perm' : d} value={d === null ? 'null' : d}>
                        {durationLabel(d)}
                      </option>
                    ))}
                  </select>
                </div>
                <p className="mt-1 text-[10px] text-white/40">
                  When it ends, the connection closes automatically and synced mail is cleared. Permanent = no expiry.
                </p>
              </div>

              {(busy || phases) && (
                <ConnectProgress active={busy} phases={phases} error={connectError} done={connectDone} />
              )}

              <button type="submit" disabled={busy} className="btn-primary w-full py-2.5">
                {busy ? <><RefreshCw className="w-4 h-4 animate-spin" /><span>Connecting…</span></>
                  : <><Check className="w-4 h-4" /><span>Connect Gmail</span></>}
              </button>

              <ol className="list-decimal list-inside space-y-1 text-[11px] text-white/50 glass-soft p-3">
                <li>
                  Turn on{' '}
                  <a className="text-white underline" target="_blank" rel="noreferrer" href="https://myaccount.google.com/signinoptions/two-step-verification">
                    2-Step Verification <ExternalLink className="w-2.5 h-2.5 inline" />
                  </a>
                </li>
                <li>
                  Enable IMAP:{' '}
                  <a className="text-white underline" target="_blank" rel="noreferrer" href="https://mail.google.com/mail/u/0/#settings/fwdandpop">
                    Gmail → Forwarding and POP/IMAP <ExternalLink className="w-2.5 h-2.5 inline" />
                  </a>{' '}→ &ldquo;Enable IMAP&rdquo; → Save.
                </li>
                <li>
                  Generate an App Password:{' '}
                  <a className="text-white underline" target="_blank" rel="noreferrer" href="https://myaccount.google.com/apppasswords">
                    myaccount.google.com/apppasswords <ExternalLink className="w-2.5 h-2.5 inline" />
                  </a>{' '}— name it &ldquo;PhishGuard&rdquo;, copy the 16 characters.
                </li>
              </ol>
            </form>
          )}

          {msg && (
            <div className={`glass-soft p-3 text-[11px] leading-relaxed ${msg.ok ? 'text-white/80' : 'text-white'}`}>
              <div className="flex items-start gap-2">
                {msg.ok ? <ShieldCheck className="w-3.5 h-3.5 mt-0.5 shrink-0" /> : <AlertCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />}
                <p>{msg.text}</p>
              </div>
            </div>
          )}

          <div className="flex items-center gap-1.5 text-[10px] text-white/35">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Read-only. App password encrypted at rest, scoped to this browser session, wiped on disconnect.</span>
          </div>
        </div>
    </Modal>
  );
}
