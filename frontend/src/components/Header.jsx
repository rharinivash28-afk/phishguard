import React from 'react';
import { Shield, ShieldAlert, Mail, Activity, Settings, Zap, Terminal } from 'lucide-react';

function GoogleGlyph({ className = 'w-4 h-4' }) {
  return (
    <span className={`inline-flex items-center justify-center rounded-full bg-black text-white font-black ${className}`}>
      G
    </span>
  );
}

export default function Header({
  activeTab,
  setActiveTab,
  stats,
  onOpenSettings,
  onOpenOAuthModal,
  onStartOAuthLogin,
  onSimulateAttack,
}) {
  const isOAuthConnected = stats?.oauth?.is_connected || stats?.imap_connected;
  const userEmail = stats?.oauth?.user_email || stats?.connected_email || 'harinivash28082007@gmail.com';

  const tabs = [
    { id: 'sentinel', label: 'Inbox Sentinel', Icon: Activity },
    { id: 'investigator', label: 'Deep Forensics', Icon: Terminal },
    { id: 'reports', label: 'Cybercrime Reports', Icon: ShieldAlert },
  ];

  return (
    <header className="sticky top-0 z-40 border-b border-white/10 bg-black/40 backdrop-blur-2xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-3">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-white text-black">
              <Shield className="w-5 h-5" />
              {stats?.threats_blocked > 0 && (
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-70" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-white" />
                </span>
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-lg tracking-tight text-white">PhishGuard AI</span>
                <span className="hidden sm:inline pill-muted">PS-02 Sentinel</span>
              </div>
              <p className="text-xs text-white/40 hidden sm:block">24/7 Phishing Forensics &amp; Cybercrime Defense</p>
            </div>
          </div>

          {/* Nav */}
          <nav className="hidden lg:flex items-center gap-1 glass-soft p-1">
            {tabs.map(({ id, label, Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  activeTab === id
                    ? 'bg-white text-black'
                    : 'text-white/50 hover:text-white hover:bg-white/[0.06]'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{label}</span>
              </button>
            ))}
          </nav>

          {/* Controls */}
          <div className="flex items-center gap-2">
            <button
              onClick={onSimulateAttack}
              title="Simulate an incoming phishing attack"
              className="hidden md:inline-flex btn-ghost"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Inject Phish</span>
            </button>

            {isOAuthConnected ? (
              <button
                onClick={onOpenOAuthModal}
                title="Gmail connected — click to switch account or disconnect"
                className="flex items-center gap-2 glass-soft px-3 py-1.5 cursor-pointer hover:bg-white/[0.09] transition"
              >
                <span className="w-2 h-2 rounded-full shrink-0 dot-safe animate-pulse" />
                <Mail className="w-3.5 h-3.5 text-white/70 shrink-0" />
                <span className="font-mono text-xs text-white/85 font-semibold truncate max-w-[160px]">{userEmail}</span>
              </button>
            ) : (
              <button
                onClick={onStartOAuthLogin}
                title="Sign in with Google to connect your Gmail"
                className="flex items-center gap-2 rounded-lg bg-white text-black px-3 py-1.5 text-xs font-bold hover:bg-white/85 transition"
              >
                <GoogleGlyph className="w-4 h-4 text-[10px]" />
                <span>Sign in with Google</span>
              </button>
            )}

            <button onClick={onOpenSettings} title="Settings" className="p-2 rounded-lg glass-soft text-white/70 hover:text-white hover:bg-white/[0.09] transition">
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Mobile nav */}
        <nav className="lg:hidden flex items-center gap-1 glass-soft p-1 mb-3">
          {tabs.map(({ id, label, Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg text-[11px] font-semibold transition ${
                activeTab === id ? 'bg-white text-black' : 'text-white/50 hover:text-white'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{label}</span>
            </button>
          ))}
        </nav>
      </div>
    </header>
  );
}
