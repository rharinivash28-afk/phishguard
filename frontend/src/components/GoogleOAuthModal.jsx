import React, { useState } from 'react';
import {
  X, RefreshCw, Check, ExternalLink, LogOut, ChevronDown, Copy, ShieldCheck, Mail, Key, Eye, EyeOff
} from 'lucide-react';

function GoogleGlyph({ className = 'w-4 h-4' }) {
  return (
    <span className={`inline-flex items-center justify-center rounded-full bg-white text-black font-black ${className}`}>
      G
    </span>
  );
}

export default function GoogleOAuthModal({
  stats,
  onClose,
  onSaveOAuthCreds,
  onStartOAuthLogin,
  onDirectTokenConnect,
  onOAuthDisconnect,
  onTriggerOAuthSync,
  onSaveGmailConfig,
  onTriggerScan,
}) {
  const oauth = stats?.oauth || {};
  const oauthConnected = oauth.is_connected;
  const imapConnected = stats?.imap_connected;
  const isConnected = oauthConnected || imapConnected;
  const sharedClient = oauth.shared_client;               // operator baked in one OAuth client
  const clientConfigured = oauth.client_id_configured;    // shared OR user-provided
  const redirectUri = oauth.redirect_uri || 'http://localhost:5173/api/auth/google/callback';

  // When the deployment ships a shared Google client, sign-in is the easy path.
  const [tab, setTab] = useState(sharedClient ? 'google' : 'app'); // 'app' | 'google'

  // ---- App password state
  const [email, setEmail] = useState(stats?.connected_email || oauth.user_email || '');
  const [appPassword, setAppPassword] = useState('');
  const [showAppPassword, setShowAppPassword] = useState(false);
  const [connectingImap, setConnectingImap] = useState(false);
  const [imapMsg, setImapMsg] = useState(null);

  // ---- Google OAuth state
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [savingCreds, setSavingCreds] = useState(false);
  const [credMsg, setCredMsg] = useState(null);
  const [showSetup, setShowSetup] = useState(!clientConfigured);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [copied, setCopied] = useState(false);
  const [directToken, setDirectToken] = useState('');
  const [tokenEmail, setTokenEmail] = useState(oauth.user_email || 'you@gmail.com');
  const [connecting, setConnecting] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const copyRedirect = () => {
    navigator.clipboard.writeText(redirectUri);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const handleConnectImap = async (e) => {
    e.preventDefault();
    if (!email || !appPassword) return;
    setConnectingImap(true);
    setImapMsg(null);
    const res = await onSaveGmailConfig(email.trim(), appPassword);
    setConnectingImap(false);
    if (res?.connected) {
      setImapMsg({ ok: true, text: `Connected. ${res.new_emails_found ?? 0} recent messages pulled in.` });
    } else {
      setImapMsg({
        ok: false,
        text: res?.error
          ? `Gmail rejected the login. ${res.error}`
          : 'Gmail rejected the login. Check the steps below, then retry.',
      });
    }
  };

  const handleSaveCreds = async (e) => {
    e.preventDefault();
    if (!clientId || !clientSecret) return;
    setSavingCreds(true);
    setCredMsg(null);
    const res = await onSaveOAuthCreds(clientId.trim(), clientSecret.trim());
    setSavingCreds(false);
    if (res === true || res?.ok) {
      setShowSetup(false);
    } else {
      setCredMsg(res?.error || 'Could not save those credentials.');
    }
  };

  const handleConnectDirectToken = async (e) => {
    e.preventDefault();
    if (!directToken) return;
    setConnecting(true);
    await onDirectTokenConnect(tokenEmail, directToken.trim());
    setConnecting(false);
  };

  const handleSyncNow = async () => {
    setSyncing(true);
    if (oauthConnected) await onTriggerOAuthSync();
    else await onTriggerScan?.();
    setSyncing(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-md overflow-y-auto">
      <div className="glass-hi w-full max-w-lg overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-white text-black flex items-center justify-center"><Mail className="w-5 h-5" /></div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white">Connect your Gmail</h3>
                <span className={`px-2 py-0.5 text-[9px] font-bold uppercase rounded-full border ${
                  isConnected ? 'bg-white text-black border-white' : 'bg-white/[0.06] text-white/50 border-white/15'
                }`}>
                  {isConnected ? 'Connected' : 'Not connected'}
                </span>
              </div>
              <p className="text-xs text-white/45">Two ways in &mdash; app password or Google sign-in.</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 text-white/40 hover:text-white rounded-lg transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4 text-xs">
          {/* Connected banner */}
          {isConnected && (
            <div className="glass-soft p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-white text-black flex items-center justify-center font-bold uppercase">
                  {(oauth.user_name || oauth.user_email || stats?.connected_email || 'G')[0]}
                </div>
                <div>
                  <p className="font-bold text-white text-xs">
                    {oauthConnected ? (oauth.user_name || 'Google Account') : 'IMAP app-password'}
                  </p>
                  <p className="text-[11px] text-white/50 font-mono">{oauth.user_email || stats?.connected_email}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={handleSyncNow} disabled={syncing} className="btn-ghost">
                  <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
                  <span>Sync</span>
                </button>
                {oauthConnected && (
                  <>
                    <button onClick={onStartOAuthLogin} className="btn-ghost" title="Sign in with a different Google account">
                      Switch account
                    </button>
                    <button onClick={onOAuthDisconnect} title="Disconnect" className="p-2 rounded-xl bg-white/[0.06] border border-white/12 text-white/50 hover:text-white hover:bg-white/[0.12] transition">
                      <LogOut className="w-4 h-4" />
                    </button>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="flex items-center gap-1 glass-soft p-1">
            <button onClick={() => setTab('app')}
              className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition ${
                tab === 'app' ? 'bg-white text-black' : 'text-white/50 hover:text-white'
              }`}>
              <Key className="w-3.5 h-3.5" /> App password
            </button>
            <button onClick={() => setTab('google')}
              className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition ${
                tab === 'google' ? 'bg-white text-black' : 'text-white/50 hover:text-white'
              }`}>
              <GoogleGlyph className="w-3.5 h-3.5 text-[9px]" /> Google sign-in
            </button>
          </div>

          {/* ---- APP PASSWORD ---- */}
          {tab === 'app' && (
            <form onSubmit={handleConnectImap} className="space-y-3">
              <p className="text-[11px] text-white/50 leading-relaxed">
                Fastest way &mdash; no Google Cloud project. Enable IMAP in Gmail, generate a 16-character App Password, paste it here.
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
                  <input type={showAppPassword ? 'text' : 'password'} required value={appPassword}
                    onChange={(e) => setAppPassword(e.target.value)}
                    placeholder="abcd efgh ijkl mnop" className="glass-input pl-9 pr-10 font-mono" />
                  <button type="button" onClick={() => setShowAppPassword((v) => !v)}
                    title={showAppPassword ? 'Hide' : 'Show'}
                    className="absolute right-2.5 top-2 p-0.5 text-white/40 hover:text-white transition">
                    {showAppPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {appPassword && (
                  <p className="mt-1 text-[10px] text-white/40 font-mono">
                    {appPassword.replace(/\s+/g, '').length} / 16 characters
                  </p>
                )}
              </div>

              <button type="submit" disabled={connectingImap} className="btn-primary w-full py-2.5">
                {connectingImap ? <><RefreshCw className="w-4 h-4 animate-spin" /><span>Connecting…</span></>
                  : <><Check className="w-4 h-4" /><span>Connect Gmail</span></>}
              </button>

              {imapMsg && (
                <div className={`glass-soft p-3 text-[11px] leading-relaxed space-y-2 ${imapMsg.ok ? 'text-white/80' : 'text-white'}`}>
                  <p>{imapMsg.text}</p>
                  {!imapMsg.ok && (
                    <div className="flex flex-wrap gap-2 pt-1">
                      <a className="btn-ghost !py-1 !px-2 text-[10px]" target="_blank" rel="noreferrer"
                        href="https://myaccount.google.com/signinoptions/two-step-verification">
                        1. Turn on 2-Step Verification <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                      <a className="btn-ghost !py-1 !px-2 text-[10px]" target="_blank" rel="noreferrer"
                        href="https://mail.google.com/mail/u/0/#settings/fwdandpop">
                        2. Enable IMAP <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                      <a className="btn-ghost !py-1 !px-2 text-[10px]" target="_blank" rel="noreferrer"
                        href="https://myaccount.google.com/apppasswords">
                        3. New App Password <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </div>
                  )}
                </div>
              )}

              <ol className="list-decimal list-inside space-y-1 text-[11px] text-white/50 glass-soft p-3">
                <li>
                  Enable IMAP:{' '}
                  <a className="text-white underline" target="_blank" rel="noreferrer"
                     href="https://mail.google.com/mail/u/0/#settings/fwdandpop">
                    Gmail → Forwarding and POP/IMAP <ExternalLink className="w-2.5 h-2.5 inline" />
                  </a>{' '}→ &ldquo;Enable IMAP&rdquo; → Save.
                </li>
                <li>
                  Generate an App Password:{' '}
                  <a className="text-white underline" target="_blank" rel="noreferrer"
                     href="https://myaccount.google.com/apppasswords">
                    myaccount.google.com/apppasswords <ExternalLink className="w-2.5 h-2.5 inline" />
                  </a>{' '}(needs 2-Step Verification on). Name it &ldquo;PhishGuard&rdquo;, copy the 16 characters.
                </li>
                <li>Paste it above &mdash; spaces are fine.</li>
              </ol>
            </form>
          )}

          {/* ---- GOOGLE SIGN-IN ---- */}
          {tab === 'google' && sharedClient && (
            <div className="space-y-4">
              <p className="text-[11px] text-white/55 leading-relaxed">
                Sign in with your Google account and pick the Gmail you want monitored. Read-only, and you can
                revoke it anytime from your Google account.
              </p>
              <button
                onClick={onStartOAuthLogin}
                className="w-full py-3 rounded-xl bg-white text-black font-bold text-sm flex items-center justify-center gap-2 hover:bg-white/85 transition"
              >
                <GoogleGlyph className="w-5 h-5" />
                <span>Sign in with Google</span>
              </button>
              <p className="text-[10px] text-white/35 leading-relaxed">
                On the consent screen you may see &ldquo;Google hasn&rsquo;t verified this app&rdquo; while it&rsquo;s in
                testing &mdash; click <strong className="text-white/60">Advanced &rarr; Go to PhishGuard (unsafe)</strong> to continue.
              </p>
            </div>
          )}

          {/* ---- GOOGLE SIGN-IN (bring-your-own client, local/dev) ---- */}
          {tab === 'google' && !sharedClient && (
            <div className="space-y-4">
              <div className="glass-soft p-3 text-[11px] text-white/55 leading-relaxed">
                This build has no shared Google client, so you supply a one-time
                <strong className="text-white/80"> OAuth client</strong> (Client ID ends in
                <code className="font-mono text-white/75"> .apps.googleusercontent.com</code>, Secret starts with
                <code className="font-mono text-white/75"> GOCSPX-</code>). A Gmail address / App Password will
                <strong className="text-white/80"> not</strong> work here &mdash;{' '}
                <button type="button" onClick={() => setTab('app')} className="text-white underline">use the App password tab</button>.
              </div>
              {clientConfigured && (
                <button onClick={onStartOAuthLogin}
                  className="w-full py-3 rounded-xl bg-white text-black font-bold text-sm flex items-center justify-center gap-2 hover:bg-white/85 transition">
                  <GoogleGlyph className="w-5 h-5" />
                  <span>Sign in with Google</span>
                </button>
              )}

              <div>
                <button onClick={() => setShowSetup(!showSetup)}
                  className="w-full flex items-center justify-between text-white/60 hover:text-white transition py-1">
                  <span className="font-semibold uppercase tracking-wider text-[11px]">
                    {clientConfigured ? 'Update OAuth credentials' : 'One-time setup — OAuth credentials'}
                  </span>
                  <ChevronDown className={`w-4 h-4 transition ${showSetup ? 'rotate-180' : ''}`} />
                </button>
                {showSetup && (
                  <form onSubmit={handleSaveCreds} className="mt-2 space-y-3">
                    <ol className="list-decimal list-inside space-y-1 text-[11px] text-white/50 glass-soft p-3">
                      <li>Open{' '}
                        <a className="text-white underline" target="_blank" rel="noreferrer"
                           href="https://console.cloud.google.com/apis/credentials">
                          Google Cloud → Credentials <ExternalLink className="w-2.5 h-2.5 inline" />
                        </a>
                      </li>
                      <li>Create <strong className="text-white/80">OAuth client ID</strong> → <strong className="text-white/80">Web application</strong></li>
                      <li className="flex flex-wrap items-center gap-1">
                        <strong className="text-white/80">Authorized redirect URI</strong>:
                        <code className="bg-white/10 px-1.5 py-0.5 rounded font-mono text-white/80 break-all">{redirectUri}</code>
                        <button type="button" onClick={copyRedirect} className="text-white/50 hover:text-white">
                          {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </li>
                      <li>Enable the <strong className="text-white/80">Gmail API</strong></li>
                    </ol>
                    <input type="text" required value={clientId} onChange={(e) => setClientId(e.target.value)}
                      placeholder="xxxxxx.apps.googleusercontent.com" className="glass-input font-mono" />
                    <input type="password" required value={clientSecret} onChange={(e) => setClientSecret(e.target.value)}
                      placeholder="GOCSPX-••••••••••••" className="glass-input font-mono" />
                    <button type="submit" disabled={savingCreds} className="btn-primary w-full">
                      {savingCreds ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                      <span>Save credentials</span>
                    </button>
                    {credMsg && <div className="glass-soft p-3 text-[11px] text-white leading-relaxed">{credMsg}</div>}
                  </form>
                )}
              </div>

              <div className="border-t border-white/10 pt-1">
                <button onClick={() => setShowAdvanced(!showAdvanced)}
                  className="w-full flex items-center justify-between text-white/45 hover:text-white/80 transition py-2">
                  <span className="text-[11px] uppercase tracking-wider font-semibold">Advanced — paste an access token</span>
                  <ChevronDown className={`w-4 h-4 transition ${showAdvanced ? 'rotate-180' : ''}`} />
                </button>
                {showAdvanced && (
                  <form onSubmit={handleConnectDirectToken} className="space-y-3 pt-1">
                    <input type="email" required value={tokenEmail} onChange={(e) => setTokenEmail(e.target.value)}
                      placeholder="you@gmail.com" className="glass-input" />
                    <textarea rows={3} required value={directToken} onChange={(e) => setDirectToken(e.target.value)}
                      placeholder="OAuth access token (ya29...) from the Google OAuth Playground" className="glass-input font-mono" />
                    <div className="flex items-center justify-between">
                      <a href="https://developers.google.com/oauthplayground" target="_blank" rel="noreferrer"
                        className="text-[10px] text-white/50 hover:text-white flex items-center gap-0.5">
                        <span>OAuth Playground</span><ExternalLink className="w-2.5 h-2.5" />
                      </a>
                      <button type="submit" disabled={connecting} className="btn-ghost">
                        {connecting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                        <span>Connect with token</span>
                      </button>
                    </div>
                  </form>
                )}
              </div>
            </div>
          )}

          <div className="flex items-center gap-1.5 text-[10px] text-white/35">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Read-only. Credentials stay on your machine (<code className="font-mono">backend/.env</code>).</span>
          </div>
        </div>
      </div>
    </div>
  );
}
