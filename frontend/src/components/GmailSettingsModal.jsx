import React, { useState } from 'react';
import { X, Mail, Key, Check, RefreshCw, AlertCircle, ExternalLink, HelpCircle, Sparkles } from 'lucide-react';

export default function GmailSettingsModal({ stats, onClose, onSaveConfig, onToggleMonitoring, onTriggerScan }) {
  const [email, setEmail] = useState(stats?.oauth?.user_email || stats?.connected_email || 'harinivash28082007@gmail.com');
  const [appPassword, setAppPassword] = useState('');
  const [active, setActive] = useState(stats?.monitoring_active ?? true);
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setTesting(true);
    await onSaveConfig(email, appPassword);
    await onToggleMonitoring(active);
    setTesting(false);
    setSaved(true);
    setTimeout(() => { setSaved(false); onClose(); }, 1200);
  };

  const handleSwitchToDemoMode = async () => {
    setTesting(true);
    await onSaveConfig(email, '');
    await onToggleMonitoring(true);
    setTesting(false);
    setSaved(true);
    setTimeout(() => { setSaved(false); onClose(); }, 1000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md overflow-y-auto">
      <div className="glass-hi w-full max-w-lg overflow-hidden">
        <div className="p-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-white/[0.06] text-white/80 border border-white/15"><Mail className="w-5 h-5" /></div>
            <div>
              <h3 className="text-sm font-bold text-white">Gmail 24/7 Sentinel Guard</h3>
              <p className="text-xs text-white/45">Automated phishing analysis &amp; quarantine</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 text-white/40 hover:text-white rounded-lg transition"><X className="w-5 h-5" /></button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs">
          <div className="glass-soft p-4 flex items-center justify-between">
            <div>
              <p className="font-bold text-white text-xs flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${active ? 'bg-white animate-pulse' : 'bg-white/30'}`} />
                24/7 Active Inbox Sentinel
              </p>
              <p className="text-[11px] text-white/45 mt-0.5">Silently scans incoming mail and auto-blocks phishing threats.</p>
            </div>
            <button type="button" onClick={() => setActive(!active)}
              className={`w-12 h-6 flex items-center rounded-full p-1 transition ${active ? 'bg-white justify-end' : 'bg-white/15 justify-start'}`}>
              <div className={`w-4 h-4 rounded-full ${active ? 'bg-black' : 'bg-white/70'}`} />
            </button>
          </div>

          <div className="glass-soft p-3 text-[11px] text-white/55 leading-relaxed flex items-start gap-2">
            <Sparkles className="w-3.5 h-3.5 mt-0.5 shrink-0" />
            <span>The easiest way to connect is <strong className="text-white/80">Connect Gmail</strong> in the header (one-click Google sign-in). The fields below are an alternative using an IMAP app password.</span>
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase text-white/45 mb-1">Your monitored Gmail address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-white/35 absolute left-3 top-2.5" />
              <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
                placeholder="your.email@gmail.com" className="glass-input pl-9" />
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="block text-[11px] font-semibold uppercase text-white/45">16-letter Google app password</label>
              <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noreferrer"
                className="text-[11px] text-white/50 hover:text-white flex items-center gap-1">
                <HelpCircle className="w-3.5 h-3.5" /><span>Get app password</span>
              </a>
            </div>
            <div className="relative">
              <Key className="w-4 h-4 text-white/35 absolute left-3 top-2.5" />
              <input type="password" value={appPassword} onChange={(e) => setAppPassword(e.target.value)}
                placeholder="celg uekr qlkq wpxr" className="glass-input pl-9 font-mono" />
            </div>
          </div>

          <div className="glass-soft p-4 space-y-2 text-[11px] text-white/55">
            <h5 className="font-bold text-white/80 uppercase tracking-wide flex items-center gap-1.5">
              <AlertCircle className="w-4 h-4" /> If Gmail IMAP rejects authentication
            </h5>
            <p>
              1. Enable IMAP in{' '}
              <a href="https://mail.google.com/mail/u/0/#settings/fwdandpop" target="_blank" rel="noreferrer" className="text-white underline inline-flex items-center gap-0.5">
                Gmail Settings → POP/IMAP <ExternalLink className="w-2.5 h-2.5" />
              </a>, then Save Changes.
            </p>
            <p>2. Generate a fresh 16-letter app password while signed in as <code className="font-mono text-white/75">{email}</code>.</p>
            <div className="pt-2 border-t border-white/10 flex items-center justify-between">
              <span className="text-[10px] text-white/40">Want to test the full system right now?</span>
              <button type="button" onClick={handleSwitchToDemoMode} className="btn-ghost">
                <Sparkles className="w-3 h-3" /><span>Use simulated guard</span>
              </button>
            </div>
          </div>

          <div className="pt-2 flex flex-col sm:flex-row justify-between items-center gap-2">
            <button type="button" onClick={onTriggerScan} className="btn-ghost w-full sm:w-auto">
              <RefreshCw className="w-3.5 h-3.5" /><span>Test live scan</span>
            </button>
            <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
              <button type="button" onClick={onClose} className="btn-ghost">Cancel</button>
              <button type="submit" disabled={testing} className="btn-primary">
                {testing ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /><span>Testing…</span></>
                  : saved ? <><Check className="w-4 h-4" /><span>Saved</span></>
                  : <span>Save &amp; connect</span>}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
