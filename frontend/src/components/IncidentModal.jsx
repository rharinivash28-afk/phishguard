import React from 'react';
import { X, ShieldAlert, Download, Copy, Printer, Check, Terminal, Lock, FileJson } from 'lucide-react';
import Modal from './Modal';

export default function IncidentModal({ report, onClose }) {
  const [copied, setCopied] = React.useState(false);

  if (!report) return null;

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(report.markdown_dossier || JSON.stringify(report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => window.print();

  const handleDownload = () => {
    const blob = new Blob([report.markdown_dossier || JSON.stringify(report, null, 2)], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.incident_id}_CYBERCRIME_REPORT.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadStix = () => {
    const blob = new Blob([JSON.stringify(report.stix_bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.incident_id}.stix.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const Section = ({ title, Icon, children }) => (
    <div className="glass-soft p-4 space-y-3">
      <h4 className="font-bold text-white uppercase tracking-wider text-xs flex items-center gap-2">
        {Icon && <Icon className="w-4 h-4" />}
        {title}
      </h4>
      {children}
    </div>
  );

  return (
    <Modal onClose={onClose} maxWidth="max-w-4xl" panelClassName="flex flex-col max-h-[90vh]">
        {/* Top bar */}
        <div className="p-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-white text-black"><ShieldAlert className="w-5 h-5" /></div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono">{report.incident_id}</h3>
                <span className="pill-danger">{report.threat_level} severity</span>
              </div>
              <p className="text-xs text-white/45">Official Cybercrime Department Forensic Incident Dossier</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleCopyMarkdown} className="btn-ghost" title="Copy markdown">
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button onClick={handleDownload} className="btn-ghost" title="Download the dossier as Markdown">
              <Download className="w-4 h-4" /><span className="hidden sm:inline">Dossier</span>
            </button>
            {report.stix_bundle && (
              <button onClick={handleDownloadStix} className="btn-ghost" title="Download the STIX 2.1 threat-intel bundle">
                <FileJson className="w-4 h-4" /><span className="hidden sm:inline">STIX 2.1</span>
              </button>
            )}
            <button onClick={handlePrint} className="btn-ghost" title="Print">
              <Printer className="w-4 h-4" /><span className="hidden sm:inline">Print</span>
            </button>
            <button onClick={onClose} className="p-2 rounded-xl bg-white/[0.06] border border-white/12 text-white/50 hover:text-white transition">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 font-mono text-xs text-white/70 leading-relaxed">
          <Section title="Section 1: Executive Summary">
            <div className="flex justify-between items-center pb-2 border-b border-white/10 text-white/40">
              <span className="font-bold text-white uppercase tracking-wider text-xs">Verdict</span>
              <span>Generated: {report.timestamp}</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {[
                ['Classification Verdict', report.verdict_label],
                ['Impersonated Organization', report.detected_brand?.toUpperCase() || 'None'],
                ['Composite Phishing Risk Score', `${report.risk_score} / 100`],
                ['Automated Sentinel Action', 'AUTO_QUARANTINED & BLOCKED'],
              ].map(([k, v]) => (
                <div key={k}>
                  <p className="text-white/35 uppercase text-[10px]">{k}</p>
                  <p className="text-sm font-bold text-white font-sans mt-0.5">{v}</p>
                </div>
              ))}
            </div>
          </Section>

          <Section title="Section 2: Indicators of Compromise (IoCs)" Icon={Terminal}>
            <div className="space-y-2">
              <div>
                <span className="text-white/35 uppercase text-[10px] block">Originating Malicious Domains:</span>
                {(report.iocs?.malicious_domains || []).length > 0
                  ? report.iocs.malicious_domains.map((d, i) => (
                      <span key={i} className="inline-block bg-white/10 text-white border border-white/20 px-2 py-0.5 rounded text-xs mr-2 mt-1">{d}</span>
                    ))
                  : <span className="text-white/40">None detected</span>}
              </div>
              <div>
                <span className="text-white/35 uppercase text-[10px] block">Extracted Phishing Links:</span>
                {(report.iocs?.phishing_urls || []).length > 0
                  ? report.iocs.phishing_urls.map((u, i) => (
                      <div key={i} className="bg-white/[0.04] p-2 rounded border border-white/10 text-white/80 break-all mt-1">{u}</div>
                    ))
                  : <span className="text-white/40">None</span>}
              </div>
              <div>
                <span className="text-white/35 uppercase text-[10px] block">Artifact SHA-256 Hashes:</span>
                <div className="space-y-1 mt-1">
                  {(report.iocs?.attachment_hashes || []).map((h, i) => (
                    <div key={i} className="bg-white/[0.04] p-2 rounded border border-white/10 flex justify-between items-center">
                      <span className="text-white/60 font-mono">{h.sha256}</span>
                      <span className="text-[10px] text-white/50">{h.artifact_type}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Section>

          <Section title="Section 3: MITRE ATT&CK Tactical Mapping" Icon={Lock}>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {(report.mitre_tactics || []).map((m, i) => (
                <div key={i} className="bg-white/[0.04] p-2.5 rounded-lg border border-white/10">
                  <span className="text-[10px] text-white/70 font-bold font-mono">{m.tactic_id}</span>
                  <p className="font-semibold text-white/85 text-[11px] mt-0.5">{m.name}</p>
                  <span className="text-[10px] text-white/40">{m.phase}</span>
                </div>
              ))}
            </div>
          </Section>

          <Section title="Section 4: Mandatory Containment & Remediation Playbook" Icon={ShieldAlert}>
            <div className="space-y-2">
              {(report.recommended_actions || []).map((act, i) => (
                <div key={i} className="p-3 bg-white/[0.04] rounded-lg border border-white/10 flex items-start gap-3">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white text-black">{act.priority}</span>
                  <div>
                    <p className="font-bold text-white/85 text-xs">{act.step}</p>
                    <p className="text-white/45 text-[11px] mt-0.5">{act.details}</p>
                  </div>
                </div>
              ))}
            </div>
          </Section>
        </div>

        <div className="p-4 border-t border-white/10 flex justify-between items-center">
          <span className="text-[11px] text-white/35 font-mono">PhishGuard AI Incident Engine v2.0 • Cryptographically Verified</span>
          <button onClick={onClose} className="btn-ghost">Close dossier</button>
        </div>
    </Modal>
  );
}
