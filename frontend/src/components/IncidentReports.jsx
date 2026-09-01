import React, { useState } from 'react';
import { ShieldAlert, Eye, Search } from 'lucide-react';

export default function IncidentReports({ reports, onViewReport }) {
  const [search, setSearch] = useState('');

  const filtered = (reports || []).filter(r =>
    r.incident_id?.toLowerCase().includes(search.toLowerCase()) ||
    r.verdict_label?.toLowerCase().includes(search.toLowerCase()) ||
    r.detected_brand?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="glass p-5 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-white/70" />
            <h2 className="text-base font-bold text-white uppercase tracking-wide">Cybercrime Department Incident Reports</h2>
          </div>
          <p className="text-xs text-white/45 mt-1">Auto-generated forensic dossiers formatted for CERT, cyber police, and SOC containment.</p>
        </div>
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-white/40 absolute left-3 top-2.5" />
          <input type="text" placeholder="Search report ID, brand…" value={search}
            onChange={(e) => setSearch(e.target.value)} className="glass-input pl-9" />
        </div>
      </div>

      <div className="glass overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-white/70">
            <thead className="text-white/40 uppercase tracking-wider font-semibold border-b border-white/10 text-[10px]">
              <tr>
                <th className="p-4">Incident Reference</th>
                <th className="p-4">Timestamp</th>
                <th className="p-4">Targeted Brand</th>
                <th className="p-4">Risk Severity</th>
                <th className="p-4">IoCs Detected</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06] font-mono">
              {filtered.length === 0 ? (
                <tr><td colSpan={6} className="p-8 text-center text-white/35">No cybercrime incident reports found.</td></tr>
              ) : (
                filtered.map((r, i) => (
                  <tr key={i} className="hover:bg-white/[0.03] transition">
                    <td className="p-4 font-bold text-white/85">{r.incident_id}</td>
                    <td className="p-4 text-white/40 text-[11px]">{r.timestamp}</td>
                    <td className="p-4">
                      {r.detected_brand
                        ? <span className="pill-muted uppercase font-sans">{r.detected_brand}</span>
                        : <span className="text-white/35 font-sans">Generic Phish</span>}
                    </td>
                    <td className="p-4"><span className="pill-danger">{r.threat_level} ({r.risk_score}%)</span></td>
                    <td className="p-4 text-white/45">
                      {(r.iocs?.malicious_domains?.length || 0) + (r.iocs?.phishing_urls?.length || 0)} indicators
                    </td>
                    <td className="p-4 text-right">
                      <button onClick={() => onViewReport(r.incident_id)} className="btn-ghost font-sans inline-flex">
                        <Eye className="w-3.5 h-3.5" />
                        <span>View dossier</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
