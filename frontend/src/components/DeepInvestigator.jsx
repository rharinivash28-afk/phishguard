import React, { useState, useEffect } from 'react';
import {
  Terminal, FileText, Send, Sparkles, AlertOctagon, RefreshCw
} from 'lucide-react';

export default function DeepInvestigator({ initialEmail, samples, onGenerateReport, onViewReport }) {
  const [formData, setFormData] = useState({
    sender_address: 'security@paypa1-login.com',
    display_name: 'PayPal Security Team',
    subject: 'Your account will be suspended!',
    recipient: 'employee.target@company.org',
    body: 'Dear Valued Customer,\n\nWe detected suspicious unauthorized login attempts on your account from an unknown device in Moscow, Russia.\n\nYour account will be suspended within 24 hours unless you verify your identity and confirm your credentials immediately.\n\nPlease follow the link below to restore access:\nhttp://paypa1-login.com/verify\n\nFailure to comply will result in permanent account termination.\n\nPayPal Security Operations',
    urls: 'http://paypa1-login.com/verify',
    spf_status: 'FAIL',
    dkim_status: 'FAIL',
    dmarc_status: 'FAIL'
  });

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (initialEmail) {
      setFormData({
        sender_address: initialEmail.sender_address || '',
        display_name: initialEmail.display_name || '',
        subject: initialEmail.subject || '',
        recipient: initialEmail.recipient || 'user@gmail.com',
        body: initialEmail.body || '',
        urls: initialEmail.urls?.map(u => u.url).join('\n') || '',
        spf_status: initialEmail.spf_status || 'FAIL',
        dkim_status: initialEmail.dkim_status || 'FAIL',
        dmarc_status: initialEmail.dmarc_status || 'FAIL'
      });
      if (initialEmail.analysis) {
        setResult({ analysis: initialEmail.analysis, incident_report: null });
      }
    }
  }, [initialEmail]);

  const loadSample = (sample) => {
    setFormData({
      sender_address: sample.sender_address,
      display_name: sample.display_name,
      subject: sample.subject,
      recipient: sample.recipient || 'user@gmail.com',
      body: sample.body,
      urls: sample.urls?.map(u => u.url).join('\n') || '',
      spf_status: sample.spf_status || 'FAIL',
      dkim_status: sample.dkim_status || 'FAIL',
      dmarc_status: sample.dmarc_status || 'FAIL'
    });
    setResult(null);
  };

  const handleAnalyze = async () => {
    setLoading(true);
    try {
      const urlList = formData.urls.split('\n').map(u => u.trim()).filter(Boolean).map(u => ({ url: u, anchor: '' }));
      const payload = { ...formData, urls: urlList, attachments: [] };
      const res = await fetch('/api/analyze', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      setResult(await res.json());
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const analysis = result?.analysis;
  const score = analysis?.risk_score ?? 0;
  const riskClass = score >= 70 ? 'risk-high' : score >= 35 ? 'risk-med' : 'risk-low';
  const isPhish = score >= 50;

  const field = (label, key, opts = {}) => (
    <div>
      <label className="block text-[11px] font-semibold uppercase text-white/45 mb-1">{label}</label>
      {opts.textarea ? (
        <textarea rows={opts.rows || 3} value={formData[key]}
          onChange={(e) => setFormData({ ...formData, [key]: e.target.value })}
          placeholder={opts.placeholder} className={`glass-input ${opts.mono ? 'font-mono' : ''}`} />
      ) : (
        <input type="text" value={formData[key]}
          onChange={(e) => setFormData({ ...formData, [key]: e.target.value })}
          placeholder={opts.placeholder} className={`glass-input ${opts.mono ? 'font-mono' : ''}`} />
      )}
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Presets */}
      <div className="glass p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-white/60" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white/70">Quick Test Scenarios</h3>
          </div>
          <span className="text-[11px] text-white/35">Click a preset to auto-fill</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {(samples || []).map((sample) => (
            <button key={sample.id} onClick={() => loadSample(sample)}
              className="text-left p-2.5 rounded-lg glass-soft hover:bg-white/[0.09] transition">
              <p className="text-xs font-semibold text-white/85 truncate">{sample.title}</p>
              <p className="text-[11px] text-white/35 font-mono truncate mt-0.5">{sample.sender_address}</p>
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Input */}
        <div className="lg:col-span-5 glass p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-white/10">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-white/60" />
              <h2 className="text-sm font-bold text-white/85 uppercase tracking-wide">Investigation Input</h2>
            </div>
            <span className="pill-muted font-mono">PS-02 Spec</span>
          </div>

          <div className="space-y-3">
            {field('Sender Email Address', 'sender_address', { mono: true, placeholder: 'security@paypa1-login.com' })}
            {field('Display Name Spoofing', 'display_name', { placeholder: 'PayPal Security Team' })}
            {field('Subject Line', 'subject', { placeholder: 'Your account will be suspended!' })}
            {field('Target URLs (one per line)', 'urls', { textarea: true, rows: 2, mono: true, placeholder: 'http://paypa1-login.com/verify' })}

            <div className="grid grid-cols-3 gap-2 pt-1">
              {['spf_status', 'dkim_status', 'dmarc_status'].map((k) => (
                <div key={k}>
                  <label className="block text-[10px] font-semibold uppercase text-white/45 mb-1">{k.split('_')[0]}</label>
                  <select value={formData[k]} onChange={(e) => setFormData({ ...formData, [k]: e.target.value })}
                    className="glass-input font-mono p-1.5">
                    <option value="FAIL">FAIL</option>
                    <option value="SOFTFAIL">SOFTFAIL</option>
                    <option value="PASS">PASS</option>
                    <option value="NONE">NONE</option>
                  </select>
                </div>
              ))}
            </div>

            {field('Full Message Body & Urgency Context', 'body', { textarea: true, rows: 5, mono: true, placeholder: 'Paste email text…' })}
          </div>

          <button onClick={handleAnalyze} disabled={loading} className="btn-primary w-full py-2.5 uppercase tracking-wider">
            {loading ? <><RefreshCw className="w-4 h-4 animate-spin" /><span>Running heuristics…</span></>
              : <><Send className="w-4 h-4" /><span>Execute deep forensic analysis</span></>}
          </button>
        </div>

        {/* Results */}
        <div className="lg:col-span-7 glass p-5 space-y-5">
          {!analysis ? (
            <div className="h-full min-h-[420px] flex flex-col items-center justify-center text-center p-8 border-2 border-dashed border-white/12 rounded-xl text-white/40">
              <Terminal className="w-12 h-12 text-white/25 mb-3" />
              <p className="text-sm font-semibold text-white/70">Awaiting forensic execution</p>
              <p className="text-xs max-w-sm mt-1">
                Pick a preset or enter custom headers to see multi-factor risk scores, typosquatting math, and fired threat indicators.
              </p>
              <button onClick={handleAnalyze} className="btn-ghost mt-4">Analyze default PS-02 sample</button>
            </div>
          ) : (
            <>
              <div className={`rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${isPhish ? 'tint-danger' : 'tint-safe'}`}>
                <div>
                  <span className={isPhish ? 'pill-verdict-danger' : 'pill-verdict-safe'}>
                    {isPhish ? `${analysis.threat_level} threat detected` : 'No phishing detected'}
                  </span>
                  <h3 className={`text-lg font-extrabold mt-1 ${isPhish ? 'text-[#ff8585]' : 'text-[#6ee7a0]'}`}>{analysis.verdict_label}</h3>
                  <p className="text-xs text-white/50 mt-0.5">
                    Target domain: <span className="font-mono text-white/80">{analysis.domain}</span>
                    {analysis.detected_brand && <span className="ml-2 text-white/70 font-semibold">• Impersonating: {analysis.detected_brand.toUpperCase()}</span>}
                  </p>
                </div>
                <div className="flex items-center gap-3 bg-black/25 rounded-xl px-4 py-2.5 border border-white/10">
                  <div className="text-right">
                    <p className="text-[10px] font-semibold text-white/40 uppercase">Phishing risk</p>
                    <p className={`text-2xl font-extrabold font-mono ${riskClass}`}>{score}%</p>
                  </div>
                  <div className={`w-3 h-3 rounded-full ${isPhish ? 'dot-danger animate-pulse' : 'dot-safe'}`} />
                </div>
              </div>

              {analysis.ai_review && (
                <div className="glass-soft p-4 space-y-1.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-white/70">AI analyst second opinion — {analysis.ai_review.risk}/100</h4>
                  <p className="text-xs text-white/55 leading-relaxed">{analysis.ai_review.rationale}</p>
                  {analysis.ai_review.red_flags?.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {analysis.ai_review.red_flags.map((f, i) => (
                        <span key={i} className="px-2 py-0.5 text-[10px] font-mono rounded border border-white/15 bg-white/[0.05] text-white/60">{f}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="glass-soft p-4 space-y-2.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-white/70 mb-2">Multi-factor forensic vector breakdown</h4>
                {Object.entries(analysis.score_breakdown || {}).map(([key, val]) => (
                  <div key={key} className="space-y-1">
                    <div className="flex justify-between text-[11px] font-mono text-white/45">
                      <span className="capitalize">{key.replace('_', ' ')}</span>
                      <span className="text-white/75">{val} / 50</span>
                    </div>
                    <div className="w-full bg-white/[0.06] rounded-full h-1.5 overflow-hidden">
                      <div className="h-full rounded-full bg-white" style={{ width: `${Math.min((val / 50) * 100, 100)}%`, opacity: val >= 30 ? 1 : val >= 15 ? 0.7 : 0.4 }} />
                    </div>
                  </div>
                ))}
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-white/70 flex items-center gap-1.5">
                    <AlertOctagon className="w-4 h-4" />
                    <span>Fired indicators ({analysis.indicators?.length || 0})</span>
                  </h4>
                  <span className="text-[11px] text-white/35">Every factor explainable</span>
                </div>
                <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                  {(analysis.indicators || []).length === 0 ? (
                    <div className="p-4 glass-soft text-center text-white/40 text-xs">
                      No malicious red flags. SPF/DKIM authentication and domains are clean.
                    </div>
                  ) : (
                    analysis.indicators.map((ind, idx) => (
                      <div key={idx} className="p-3 glass-soft space-y-1">
                        <div className="flex items-center justify-between">
                          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                            ind.severity === 'CRITICAL' ? 'bg-white/12 text-white border-white/25' : 'bg-white/[0.05] text-white/60 border-white/12'
                          }`}>
                            {ind.type} (+{ind.weight})
                          </span>
                          <span className="text-[11px] font-semibold text-white/70">{ind.name}</span>
                        </div>
                        <p className="text-xs text-white/45 leading-relaxed">{ind.detail}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="pt-2 flex flex-col sm:flex-row gap-3 items-center justify-between border-t border-white/10">
                <div className="text-xs text-white/45">
                  Recommended action: <span className="font-mono text-white/80 font-semibold">{analysis.action_recommended}</span>
                </div>
                <button onClick={() => onGenerateReport(analysis, formData)} className="btn-primary w-full sm:w-auto">
                  <FileText className="w-3.5 h-3.5" />
                  <span>Generate cybercrime report</span>
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
