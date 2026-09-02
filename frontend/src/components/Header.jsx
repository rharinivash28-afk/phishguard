import React from 'react';
import { Shield, ShieldAlert, Mail, Activity, Settings, Zap, Terminal } from 'lucide-react';
import CountdownBadge from './CountdownBadge';

export default function Header({
  activeTab,
  setActiveTab,
  stats,
  connection,
  onOpenSettings,
  onConnectGmail,
  onSimulateAttack,
}) {
  const isConnected = connection?.connected || stats?.connected || stats?.imap_connected;
  const userEmail = connection?.email || stats?.connected_email || '';
  const expiresAtMs = connection?.expires_at ? Date.parse(connection.expires_at) : null;

  const tabs = [
    { id: 'sentinel', label: 'Inbox Sentinel', Icon: Activity },
    { id: 'investigator', label: 'Deep Forensics', Icon: Terminal },
    { id: 'reports', label: 'Cybercrime Reports', Icon: ShieldAlert },
  ];

  return (
    <header className="sticky top-0 z-40 border-b border-white/10 bg-black/40 backdrop-blur-2xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-2 sm:gap-3">
          {/* Brand */}
          <div className="flex items-center gap-2.5 min-w-0 shrink">
            <div className="relative flex items-center justify-center w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-white text-black shrink-0">
              <Shield className="w-5 h-5" />
              {stats?.threats_blocked > 0 && (
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-70" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-white" />
                </span>
              )}
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base sm:text-lg tracking-tight text-white whitespace-nowrap">PhishGuard AI</span>
                <span className="hidden md:inline pill-muted">Enterprise Inbox Sentinel</span>
              </div>
              <p className="text-[11px] text-white/40 hidden md:block">Zero-PII phishing forensics &amp; cybercrime reporting</p>
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
          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
            <button
              onClick={onSimulateAttack}
              title="Simulate an incoming phishing attack"
              className="hidden lg:inline-flex btn-ghost"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Inject Phish</span>
            </button>

            {isConnected ? (
              <>
                <CountdownBadge
                  expiresAt={expiresAtMs}
                  permanent={!!connection?.permanent}
                  onClick={onOpenSettings}
                />
                <button
                  onClick={onOpenSettings}
                  title="Gmail connected — click to manage or disconnect"
                  className="hidden md:flex items-center gap-2 glass-soft px-3 py-1.5 cursor-pointer hover:bg-white/[0.09] transition"
                >
                  <span className="w-2 h-2 rounded-full shrink-0 dot-safe animate-pulse" />
                  <Mail className="w-3.5 h-3.5 text-white/70 shrink-0" />
                  <span className="font-mono text-xs text-white/85 font-semibold truncate max-w-[150px]">{userEmail}</span>
                </button>
              </>
            ) : (
              <button
                onClick={onConnectGmail}
                title="Connect your Gmail with an app password"
                className="flex items-center gap-2 rounded-lg bg-white text-black px-2.5 sm:px-3 py-1.5 text-xs font-bold hover:bg-white/85 transition shrink-0"
              >
                <Mail className="w-4 h-4 shrink-0" />
                <span>Connect<span className="hidden sm:inline">&nbsp;Gmail</span></span>
              </button>
            )}

            <button onClick={onOpenSettings} title="Settings" className="p-2 rounded-lg glass-soft text-white/70 hover:text-white hover:bg-white/[0.09] transition shrink-0">
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
