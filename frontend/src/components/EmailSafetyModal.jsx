import React from 'react';
import {
  X, ShieldAlert, ShieldCheck, Lock, Eye, FileText, AlertOctagon, Mail
} from 'lucide-react';

export default function EmailSafetyModal({
  emailItem,
  onClose,
  onInspect,
  onViewReport,
  onQuarantineToggle,
}) {
  if (!emailItem) return null;

  const analysis = emailItem.analysis || {};
  const score = analysis.risk_score ?? 0;
  const isThreat = score >= 50 || emailItem.is_quarantined;
  const gmailUrl = emailItem.gmail_web_url || `https://mail.google.com/mail/u/0/#search/${encodeURIComponent(emailItem.subject)}`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md overflow-y-auto">
      <div className={`glass-hi w-full max-w-2xl overflow-hidden ${isThreat ? 'frame-danger' : 'frame-safe'}`}>
        {/* Header */}
        <div className="p-4 flex items-center justify-between border-b border-white/10">
          <div className="flex items-center gap-2.5">
            <div className={`p-2 rounded-xl border ${isThreat ? 'tint-danger text-[#ff8585]' : 'tint-safe text-[#6ee7a0]'}`}>
              {isThreat ? <AlertOctagon className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
            </div>
            <div>
              <h3 className={`text-sm font-extrabold tracking-wide uppercase ${isThreat ? 'text-[#ff8585]' : 'text-[#6ee7a0]'}`}>
                {isThreat ? 'Phishing threat detected — proceed with caution' : 'Email verified safe & authentic'}
              </h3>
              <p className="text-xs text-white/45">
                {isThreat
                  ? 'PhishGuard quarantined this email to protect your credentials & system.'
                  : 'SPF and DKIM cryptographic signatures match the originating sender.'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 text-white/40 hover:text-white rounded-lg transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5 text-xs">
          {/* Metadata */}
          <div className="glass-soft p-4 space-y-2">
            <div className="flex justify-between items-start">
              <div>
                <span className="text-[10px] text-white/40 uppercase font-semibold">Subject</span>
                <h4 className="text-sm font-bold text-white mt-0.5">{emailItem.subject}</h4>
              </div>
              <div className="text-right">
                <span className="text-[10px] text-white/40 uppercase font-semibold">Risk Score</span>
                <p className={`text-base font-extrabold font-mono ${isThreat ? 'risk-high' : 'risk-low'}`}>{score}%</p>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-white/10 text-white/45">
              <div>
                <span className="text-[10px] text-white/35 uppercase">From:</span>{' '}
                <span className="text-white/80 font-medium">{emailItem.display_name}</span>{' '}
                <span className="font-mono text-white/45 text-[11px]">&lt;{emailItem.sender_address}&gt;</span>
              </div>
              <div>
                <span className="text-[10px] text-white/35 uppercase">Domain:</span>{' '}
                <span className="font-mono text-white/80">{analysis.domain || 'Unknown'}</span>
              </div>
            </div>
          </div>

          {/* Red flags */}
          {isThreat && (
            <div className="tint-danger rounded-xl p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#ff8585] uppercase tracking-wider flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4" />
                  Why this email is dangerous
                </span>
                <span className="text-[10px] text-white/45 font-mono">{analysis.indicators?.length || 0} indicators fired</span>
              </div>
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                {(analysis.indicators || []).map((ind, i) => (
                  <div key={i} className="flex items-start gap-2 bg-black/20 p-2 rounded-lg border border-white/10">
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-[rgba(255,92,92,0.9)] text-black shrink-0 font-mono">{ind.severity}</span>
                    <span className="text-white/70 text-[11px] leading-relaxed"><strong className="text-white">{ind.name}:</strong> {ind.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AI second opinion */}
          {analysis.ai_review && (
            <div className="glass-soft p-3 space-y-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-white/55 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" /> AI analyst second opinion — {analysis.ai_review.risk}/100
              </span>
              <p className="text-[11px] text-white/60 leading-relaxed">{analysis.ai_review.rationale}</p>
              {analysis.ai_review.red_flags?.length > 0 && (
                <div className="flex flex-wrap gap-1 pt-0.5">
                  {analysis.ai_review.red_flags.map((f, i) => (
                    <span key={i} className="px-1.5 py-0.5 text-[10px] font-mono rounded border border-white/15 bg-white/[0.05] text-white/60">{f}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="glass-soft p-4 space-y-3">
            <h5 className="font-bold text-white text-xs uppercase tracking-wide">{isThreat ? 'Choose an action:' : 'Email actions:'}</h5>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <button onClick={onClose} className="btn-ghost w-full p-3">
                {isThreat ? <Lock className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                <span>{isThreat ? 'Keep blocked (recommended)' : 'Done / close'}</span>
              </button>
              <a href={gmailUrl} target="_blank" rel="noopener noreferrer" className="btn-primary w-full p-3">
                <Mail className="w-4 h-4" />
                <span>{isThreat ? 'Open original in Gmail ↗' : 'View in official Gmail ↗'}</span>
              </a>
            </div>
            {isThreat && (
              <p className="text-[10px] text-white/40 text-center">
                Opening in Gmail redirects to your official Google Mail inbox. Never click links or enter passwords inside suspicious emails.
              </p>
            )}
          </div>

          {/* Secondary */}
          <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-white/10 text-xs">
            <button onClick={() => { onClose(); onInspect(emailItem); }} className="btn-ghost">
              <Eye className="w-3.5 h-3.5" />
              <span>Full forensics workbench</span>
            </button>
            {emailItem.incident_id && (
              <button onClick={() => { onClose(); onViewReport(emailItem.incident_id); }} className="btn-primary">
                <FileText className="w-3.5 h-3.5" />
                <span>Police cybercrime dossier</span>
              </button>
            )}
            <button onClick={() => { onQuarantineToggle(emailItem.id, emailItem.is_quarantined ? 'unquarantine' : 'quarantine'); onClose(); }}
              className="text-white/40 hover:text-white transition text-[11px]">
              {emailItem.is_quarantined ? 'Release quarantine' : 'Force quarantine'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
