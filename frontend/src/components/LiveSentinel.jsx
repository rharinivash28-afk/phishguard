import React, { useState, useRef } from 'react';
import {
  ShieldAlert, ShieldCheck, Lock, Unlock, FileText, RefreshCw, Zap, Search,
  Eye, CheckCircle2, AlertOctagon, Mail, MailX, PlusCircle, Send, Upload
} from 'lucide-react';

export default function LiveSentinel({
  inbox,
  stats,
  gmailConnected = false,
  onRefresh,
  onQuarantineToggle,
  onInspectEmail,
  onViewReport,
  onSimulateAttack,
  onOpenSafetyModal,
  onIngestCustomEmail,
  onUploadEml,
  onConnectGmail,
}) {
  const [filter, setFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [showQuickIngest, setShowQuickIngest] = useState(false);

  const [customSender, setCustomSender] = useState('');
  const [customSubject, setCustomSubject] = useState('');
  const [customBody, setCustomBody] = useState('');
  const [ingesting, setIngesting] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef(null);

  const filteredItems = (inbox || []).filter(item => {
    const matchesSearch =
      item.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.sender_address.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.display_name.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;
    if (filter === 'THREATS') return item.is_quarantined || (item.analysis?.risk_score >= 50);
    if (filter === 'SAFE') return !item.is_quarantined && (item.analysis?.risk_score < 50);
    return true;
  });

  const handleQuickIngestSubmit = async (e) => {
    e.preventDefault();
    if (!customSender && !customSubject && !customBody) return;
    setIngesting(true);
    await onIngestCustomEmail({
      sender_address: customSender || 'unknown-sender@domain.com',
      display_name: customSender.split('@')[0] || 'Sender',
      subject: customSubject || 'Suspicious Email Verification',
      body: customBody || 'Please click to verify your account credentials immediately.',
      recipient: 'you@example.com',
      urls: [],
      attachments: []
    });
    setCustomSender('');
    setCustomSubject('');
    setCustomBody('');
    setIngesting(false);
    setShowQuickIngest(false);
  };

  const handleFileChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    await onUploadEml(file);
    setUploading(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const metrics = [
    { label: 'Total Scanned', value: stats?.total_emails_scanned ?? 0, sub: gmailConnected ? 'Real-time inbox sentinel' : 'Connect Gmail to begin', Icon: RefreshCw, tone: 'neutral' },
    { label: 'Threats Blocked', value: stats?.threats_blocked ?? 0, sub: 'Quarantined from inbox', Icon: ShieldAlert, tone: 'danger' },
    { label: 'Safe Deliveries', value: stats?.safe_delivered ?? 0, sub: 'SPF / DKIM / DMARC verified', Icon: ShieldCheck, tone: 'safe' },
  ];

  return (
    <div className="space-y-6">
      {/* Connect Gmail banner */}
      {!gmailConnected && (
        <div className="glass p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-white text-black"><Mail className="w-5 h-5" /></div>
            <div>
              <h3 className="text-sm font-bold text-white">Connect your Gmail for live monitoring</h3>
              <p className="text-xs text-white/45 mt-0.5">
                Read-only IMAP with a 16-character app password and a session duration you choose. You can also
                paste, upload, or simulate emails below to test the engine.
              </p>
            </div>
          </div>
          <button onClick={onConnectGmail} className="btn-primary shrink-0">
            <Mail className="w-4 h-4" />
            <span>Connect Gmail</span>
          </button>
        </div>
      )}

      {/* Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map(({ label, value, sub, Icon, tone }) => {
          const active = value > 0 && tone !== 'neutral';
          return (
            <div key={label}
              className={`glass p-4 flex items-center justify-between ${active && tone === 'danger' ? 'frame-danger' : ''} ${active && tone === 'safe' ? 'frame-safe' : ''}`}>
              <div>
                <p className="text-[11px] font-semibold text-white/45 uppercase tracking-wider">{label}</p>
                <p className={`text-2xl font-extrabold font-mono mt-1 ${
                  active && tone === 'danger' ? 'risk-high' : active && tone === 'safe' ? 'risk-low' : 'text-white'
                }`}>{value}</p>
                <p className="text-[11px] text-white/40 mt-1">{sub}</p>
              </div>
              <div className={`w-12 h-12 rounded-xl border flex items-center justify-center ${
                active && tone === 'danger' ? 'tint-danger text-[#ff8585]'
                  : active && tone === 'safe' ? 'tint-safe text-[#6ee7a0]'
                  : 'bg-white/[0.06] border-white/12 text-white/70'
              }`}>
                <Icon className="w-6 h-6" />
              </div>
            </div>
          );
        })}

        <div className="glass p-4 flex items-center justify-between">
          <div className="min-w-0">
            <p className="text-[11px] font-semibold text-white/45 uppercase tracking-wider">Monitored Mailbox</p>
            <p className="text-sm font-bold text-white/90 mt-1 font-mono truncate" title={stats?.connected_email || 'Not connected'}>
              {stats?.connected_email || 'Not connected'}
            </p>
            <p className="text-[11px] text-white/40 mt-1 flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full ${gmailConnected ? 'bg-white animate-pulse' : 'bg-white/30'}`} />
              {gmailConnected ? 'Live Gmail guard active' : 'Awaiting connection'}
            </p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-white/[0.06] border border-white/12 flex items-center justify-center text-white/70">
            <Lock className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Importer */}
      <div className="glass p-4">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-white/[0.06] text-white/80 border border-white/12">
              <Mail className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>Load any email from your Gmail inbox</span>
                <span className="pill-muted">Real-time inspector</span>
              </h3>
              <p className="text-xs text-white/45 mt-0.5">
                Paste email details, or upload a downloaded Gmail <code className="text-white/70 font-mono">.eml</code> message.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto">
            <input type="file" ref={fileInputRef} accept=".eml,.msg,.txt" onChange={handleFileChange} className="hidden" />
            <button type="button" onClick={() => fileInputRef.current?.click()} disabled={uploading} className="btn-ghost">
              <Upload className="w-3.5 h-3.5" />
              <span>{uploading ? 'Processing…' : 'Upload .eml'}</span>
            </button>
            <button type="button" onClick={() => setShowQuickIngest(!showQuickIngest)} className="btn-primary">
              <PlusCircle className="w-3.5 h-3.5" />
              <span>{showQuickIngest ? 'Close' : 'Paste email'}</span>
            </button>
          </div>
        </div>

        {showQuickIngest && (
          <form onSubmit={handleQuickIngestSubmit} className="mt-4 pt-4 border-t border-white/10 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-semibold uppercase text-white/45 mb-1">From / Sender Address</label>
                <input type="text" required value={customSender} onChange={(e) => setCustomSender(e.target.value)}
                  placeholder="security@paypa1-login.com" className="glass-input font-mono" />
              </div>
              <div>
                <label className="block text-[10px] font-semibold uppercase text-white/45 mb-1">Subject Line</label>
                <input type="text" required value={customSubject} onChange={(e) => setCustomSubject(e.target.value)}
                  placeholder="Your account will be suspended within 24 hours" className="glass-input" />
              </div>
            </div>
            <div>
              <label className="block text-[10px] font-semibold uppercase text-white/45 mb-1">Email Message Text / Links</label>
              <textarea rows={3} required value={customBody} onChange={(e) => setCustomBody(e.target.value)}
                placeholder="Paste the email body or target links here…" className="glass-input font-mono" />
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" onClick={() => setShowQuickIngest(false)} className="btn-ghost">Cancel</button>
              <button type="submit" disabled={ingesting} className="btn-primary">
                {ingesting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Classify &amp; show in feed</span>
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Stream */}
      <div className="glass overflow-hidden">
        <div className="p-4 border-b border-white/10 flex flex-col md:flex-row gap-4 items-center justify-between">
          <div className="flex items-center gap-1 glass-soft p-1 w-full md:w-auto">
            {[
              { id: 'ALL', label: `All Mail (${inbox?.length || 0})`, Icon: Mail, on: 'bg-white text-black' },
              { id: 'THREATS', label: `Phishing (${stats?.currently_quarantined || 0})`, Icon: AlertOctagon, on: 'bg-[rgba(255,92,92,0.9)] text-black', off: 'text-[#ff8585]/70 hover:text-[#ff8585]' },
              { id: 'SAFE', label: `Safe (${stats?.safe_delivered || 0})`, Icon: CheckCircle2, on: 'bg-[rgba(74,222,128,0.9)] text-black', off: 'text-[#6ee7a0]/70 hover:text-[#6ee7a0]' },
            ].map(({ id, label, Icon, on, off }) => (
              <button key={id} onClick={() => setFilter(id)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium flex items-center gap-1.5 transition ${
                  filter === id ? on : (off || 'text-white/50 hover:text-white')
                }`}>
                <Icon className="w-3.5 h-3.5" />
                <span className="whitespace-nowrap">{label}</span>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 w-full md:w-auto">
            <div className="relative flex-1 md:w-64">
              <Search className="w-4 h-4 text-white/40 absolute left-3 top-2.5" />
              <input type="text" placeholder="Search sender, subject…" value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)} className="glass-input pl-9" />
            </div>
            <button onClick={onRefresh} title="Refresh" className="p-2 rounded-lg glass-soft text-white/70 hover:text-white hover:bg-white/[0.1] transition">
              <RefreshCw className="w-4 h-4" />
            </button>
            <button onClick={onSimulateAttack} className="btn-ghost">
              <Zap className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Simulate</span>
            </button>
          </div>
        </div>

        <div className="divide-y divide-white/[0.06] max-h-[600px] overflow-y-auto">
          {!gmailConnected ? (
            <div className="p-14 text-center">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-white/[0.06] border border-white/12 flex items-center justify-center mb-4">
                <MailX className="w-8 h-8 text-white/40" />
              </div>
              <p className="text-base font-bold text-white">To see your mail, connect your Gmail to this website</p>
              <p className="text-xs text-white/45 mt-1.5 max-w-md mx-auto leading-relaxed">
                Read-only IMAP · your inbox stays private to this browser · nothing is stored except an encrypted
                app password. Or test the engine directly with paste / upload / simulate above.
              </p>
              <button onClick={onConnectGmail} className="btn-primary mt-5">
                <Mail className="w-4 h-4" />
                <span>Connect Gmail</span>
              </button>
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="p-12 text-center text-white/40">
              <ShieldCheck className="w-12 h-12 mx-auto text-white/20 mb-2" />
              <p className="text-sm font-medium">No emails match your filter</p>
            </div>
          ) : (
            filteredItems.map((item) => {
              const score = item.analysis?.risk_score ?? 0;
              const riskClass = score >= 70 ? 'risk-high' : score >= 35 ? 'risk-med' : 'risk-low';
              const isPhish = item.is_quarantined || score >= 50;

              return (
                <div
                  key={item.id}
                  onClick={() => onOpenSafetyModal(item)}
                  className={`p-4 transition cursor-pointer flex flex-col md:flex-row gap-4 justify-between items-start md:items-center hover:bg-white/[0.03] ${
                    isPhish ? 'rail-danger' : 'rail-safe'
                  }`}
                >
                  <div className="flex-1 space-y-1.5 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      {isPhish ? (
                        <span className="pill-verdict-danger"><Lock className="w-3 h-3" /> {item.is_quarantined ? 'Phishing · Quarantined' : 'Phishing'}</span>
                      ) : (
                        <span className="pill-verdict-safe"><CheckCircle2 className="w-3 h-3" /> Safe</span>
                      )}
                      {item.analysis?.detected_brand && (
                        <span className="pill-muted">Spoofing: {item.analysis.detected_brand.toUpperCase()}</span>
                      )}
                      <span className="text-[11px] text-white/35 font-mono">{item.date}</span>
                    </div>

                    <h4 className="text-sm font-semibold text-white/90 truncate">{item.subject}</h4>

                    <div className="text-xs text-white/40 flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-white/70">{item.display_name || 'No Name'}</span>
                      <span className="text-white/35 font-mono text-[11px]">&lt;{item.sender_address}&gt;</span>
                      <span className="text-white/25">•</span>
                      <span className="text-[11px]">Domain: <span className="font-mono text-white/70">{item.analysis?.domain}</span></span>
                    </div>

                    {item.analysis?.indicators?.length > 0 && (
                      <div className="flex items-center gap-1.5 pt-1 flex-wrap">
                        <span className="text-[10px] text-white/40 font-medium">Red flags ({item.analysis.indicators.length}):</span>
                        {item.analysis.indicators.slice(0, 3).map((ind, idx) => (
                          <span key={idx} title={ind.detail}
                            className={`px-1.5 py-0.5 text-[10px] font-mono rounded border ${
                              ind.severity === 'CRITICAL'
                                ? 'bg-white/12 text-white border-white/25'
                                : 'bg-white/[0.05] text-white/60 border-white/12'
                            }`}>
                            {ind.name}
                          </span>
                        ))}
                        {item.analysis.indicators.length > 3 && (
                          <span className="text-[10px] text-white/40 font-mono">+{item.analysis.indicators.length - 3} more</span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-3 w-full md:w-auto justify-between md:justify-end border-t md:border-t-0 pt-3 md:pt-0 border-white/10"
                    onClick={(e) => e.stopPropagation()}>
                    <div className="text-right">
                      <div className="flex items-center gap-2 justify-end">
                        <span className={`text-base font-extrabold font-mono ${riskClass}`}>{score}%</span>
                        <span className={`w-2.5 h-2.5 rounded-full ${isPhish ? 'dot-danger animate-pulse' : 'dot-safe'}`} />
                      </div>
                      <span className="text-[10px] font-semibold tracking-wider uppercase text-white/40">
                        {item.analysis?.threat_level || 'LOW'} risk
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <a href={item.gmail_web_url || `https://mail.google.com/mail/u/0/#search/${encodeURIComponent(item.subject)}`}
                        target="_blank" rel="noopener noreferrer" title="Open in Gmail"
                        className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-white/[0.06] text-white/80 border border-white/12 hover:bg-white/[0.12] transition flex items-center gap-1">
                        <Mail className="w-3.5 h-3.5" /><span>Gmail ↗</span>
                      </a>
                      <button onClick={() => onInspectEmail(item)} title="Deep forensics"
                        className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white/[0.06] text-white/80 border border-white/12 hover:bg-white/[0.12] transition flex items-center gap-1">
                        <Eye className="w-3.5 h-3.5" /><span>Inspect</span>
                      </button>
                      {item.incident_id && (
                        <button onClick={() => onViewReport(item.incident_id)} title="Cybercrime dossier"
                          className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-white text-black hover:bg-white/85 transition flex items-center gap-1">
                          <FileText className="w-3.5 h-3.5" /><span className="hidden sm:inline">Report</span>
                        </button>
                      )}
                      <button onClick={() => onQuarantineToggle(item.id, item.is_quarantined ? 'unquarantine' : 'quarantine')}
                        title={item.is_quarantined ? 'Release' : 'Quarantine'}
                        className="p-1.5 rounded-lg border border-white/12 bg-white/[0.06] text-white/70 hover:text-white hover:bg-white/[0.12] transition">
                        {item.is_quarantined ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
