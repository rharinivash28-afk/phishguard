/**
 * Render a full Cybercrime Incident Forensic Report to a multi-page PDF.
 * Pure client-side (jsPDF), no network, no server render. Mirrors the
 * markdown dossier the backend produces but laid out as a formal document.
 */
import { jsPDF } from 'jspdf';

const MARGIN = 48;
const LINE = 14;

export function downloadReportPdf(report) {
  if (!report) return;

  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const contentW = pageW - MARGIN * 2;
  let y = MARGIN;

  const ensureSpace = (needed = LINE) => {
    if (y + needed > pageH - MARGIN) {
      doc.addPage();
      y = MARGIN;
    }
  };

  const text = (str, opts = {}) => {
    const {
      size = 9.5,
      style = 'normal',
      color = [30, 30, 30],
      gap = LINE,
      indent = 0,
    } = opts;
    doc.setFont('helvetica', style);
    doc.setFontSize(size);
    doc.setTextColor(...color);
    const lines = doc.splitTextToSize(String(str ?? ''), contentW - indent);
    lines.forEach((ln) => {
      ensureSpace();
      doc.text(ln, MARGIN + indent, y);
      y += gap;
    });
  };

  const rule = () => {
    ensureSpace(10);
    doc.setDrawColor(200);
    doc.setLineWidth(0.5);
    doc.line(MARGIN, y, pageW - MARGIN, y);
    y += 12;
  };

  const heading = (str) => {
    ensureSpace(26);
    y += 6;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(0, 0, 0);
    doc.text(str.toUpperCase(), MARGIN, y);
    y += LINE + 2;
  };

  const kv = (k, v) => {
    ensureSpace();
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(90, 90, 90);
    doc.text(`${k}:`, MARGIN, y);
    const kw = doc.getTextWidth(`${k}: `);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(20, 20, 20);
    const lines = doc.splitTextToSize(String(v ?? '—'), contentW - kw - 4);
    doc.text(lines[0] || '—', MARGIN + kw + 4, y);
    y += LINE;
    for (let i = 1; i < lines.length; i++) {
      ensureSpace();
      doc.text(lines[i], MARGIN + kw + 4, y);
      y += LINE;
    }
  };

  // ---- Title block --------------------------------------------------------
  doc.setFillColor(15, 15, 15);
  doc.rect(0, 0, pageW, 84, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(255, 255, 255);
  doc.text('OFFICIAL CYBERCRIME INCIDENT FORENSIC REPORT', MARGIN, 40);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(190, 190, 190);
  doc.text('PhishGuard AI — Enterprise Inbox Sentinel · Security Forensics Engine', MARGIN, 58);
  doc.text(report.classification || 'RESTRICTED / LAW ENFORCEMENT & SOC DOSSIER', MARGIN, 72);
  y = 108;

  kv('Incident Reference', report.incident_id);
  kv('Report Generated', report.timestamp);
  kv('Threat Severity', `${report.threat_level} (Composite Risk Score: ${report.risk_score}/100)`);
  rule();

  // ---- 1. Executive summary ---------------------------------------------
  heading('1. Executive Summary & Verdict');
  kv('Final Verdict', report.verdict_label);
  kv('Primary Attack Vector', report.attack_vector || 'Social Engineering & Brand Impersonation Phishing');
  kv('Targeted Organization / Brand', (report.detected_brand || '').toUpperCase() || 'Unspecified Public');
  kv('Target Recipient / Victim Mailbox', report.victim_mailbox);
  kv('Automated Defensive Action Taken', report.automated_action || 'QUARANTINE_ISOLATED & BLOCKED');
  rule();

  // ---- 2. Attribution & header forensics -------------------------------
  heading('2. Attack Attribution & Header Forensics');
  kv('Sender Display Name', report.sender_display_name);
  kv('Originating Sender Address', report.sender_address);
  kv('Sender Base Domain', report.sender_domain);
  kv('Subject Line', report.subject);
  kv('SPF Authentication', report.spf_status);
  kv('DKIM Cryptographic Status', report.dkim_status);
  kv('DMARC Enforcement', report.dmarc_status);
  rule();

  // ---- 3. Fired threat indicators --------------------------------------
  const indicators = report.indicators || [];
  heading(`3. Forensic Evidence & Fired Threat Indicators (${indicators.length})`);
  if (indicators.length === 0) {
    text('No discrete threat indicators fired for this message.', { color: [110, 110, 110] });
  }
  indicators.forEach((ind, i) => {
    ensureSpace(30);
    text(`${i + 1}. [${ind.severity}]  ${ind.type}   (weight +${ind.weight})`, {
      style: 'bold', size: 9, gap: LINE - 2,
    });
    text(ind.detail, { indent: 14, size: 8.5, color: [60, 60, 60] });
    y += 2;
  });
  rule();

  // ---- 4. Indicators of Compromise ------------------------------------
  const iocs = report.iocs || {};
  heading('4. Indicators of Compromise (IoCs)');
  text('Malicious Domain(s):', { style: 'bold', size: 9, gap: LINE - 2 });
  text((iocs.malicious_domains || []).join(', ') || 'None', { indent: 14, size: 8.5 });
  y += 2;
  text('Extracted Phishing Link(s):', { style: 'bold', size: 9, gap: LINE - 2 });
  const urls = iocs.phishing_urls || [];
  if (urls.length === 0) text('None', { indent: 14, size: 8.5 });
  urls.forEach((u) => text(`• ${u}`, { indent: 14, size: 7.5, color: [50, 50, 50], gap: LINE - 3 }));
  y += 2;
  text('Cryptographic Hashes (SHA-256):', { style: 'bold', size: 9, gap: LINE - 2 });
  const hashes = iocs.attachment_hashes || [];
  if (hashes.length === 0) text('None', { indent: 14, size: 8.5 });
  hashes.forEach((h) => {
    text(`• ${h.sha256}`, { indent: 14, size: 7.5, color: [50, 50, 50], gap: LINE - 4 });
    text(`  ${h.artifact_type}: ${h.raw_value || h.filename || ''}`, {
      indent: 20, size: 6.8, color: [120, 120, 120], gap: LINE - 4,
    });
  });
  rule();

  // ---- 5. MITRE ATT&CK ----------------------------------------------
  heading('5. MITRE ATT&CK Matrix Mapping');
  (report.mitre_tactics || []).forEach((m) => {
    text(`[${m.tactic_id}]  ${m.name}  (${m.phase})`, { size: 8.5, gap: LINE - 2 });
  });
  rule();

  // ---- 6. Containment playbook -------------------------------------
  heading('6. Mandatory Containment & Remediation Playbook');
  (report.recommended_actions || []).forEach((a) => {
    ensureSpace(28);
    text(`[${a.priority}]  ${a.step}`, { style: 'bold', size: 9, gap: LINE - 2 });
    text(a.details, { indent: 14, size: 8.5, color: [60, 60, 60] });
    y += 2;
  });
  rule();

  text('Report automatically compiled and signed by the PhishGuard AI Security Forensics Engine.', {
    size: 8, style: 'italic', color: [120, 120, 120],
  });

  // ---- Footers ----------------------------------------------------
  const pages = doc.internal.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(150, 150, 150);
    doc.text(
      `${report.incident_id}  ·  CONFIDENTIAL`,
      MARGIN,
      pageH - 24,
    );
    doc.text(`Page ${p} of ${pages}`, pageW - MARGIN, pageH - 24, { align: 'right' });
  }

  doc.save(`${report.incident_id}_CYBERCRIME_REPORT.pdf`);
}
