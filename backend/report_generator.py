import datetime
import hashlib
import json
from typing import Dict, Any, List

class CybercrimeIncidentReportGenerator:
    @staticmethod
    def generate_report(
        analysis_result: Dict[str, Any],
        email_raw_data: Dict[str, Any],
        workspace_id: str = "",
    ) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Incident Reference ID — reproducible for the same email within a workspace,
        # but distinct across workspaces (the id is the DB primary key, so two
        # sessions quarantining the same sample must not collide).
        hash_input = (
            f"{workspace_id}_{analysis_result.get('sender_address')}_"
            f"{analysis_result.get('subject')}_{now.strftime('%Y%m%d')}"
        )
        incident_id = f"CC-INC-{now.strftime('%Y%m%d')}-{hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()}"
        
        sender = analysis_result.get('sender_address', 'Unknown')
        domain = analysis_result.get('domain', 'Unknown')
        subject = analysis_result.get('subject', 'No Subject')
        risk_score = analysis_result.get('risk_score', 0)
        threat_level = analysis_result.get('threat_level', 'LOW')
        verdict_label = analysis_result.get('verdict_label', 'Unknown')
        detected_brand = analysis_result.get('detected_brand', 'None')
        indicators = analysis_result.get('indicators', [])
        extracted_urls = analysis_result.get('extracted_urls', [])
        
        # Compile Indicators of Compromise (IoCs)
        iocs = {
            'malicious_domains': [domain] if risk_score >= 50 else [],
            'impersonated_brands': [detected_brand] if detected_brand else [],
            'phishing_urls': extracted_urls,
            'sender_addresses': [sender],
            'attachment_hashes': []
        }
        
        # Generate simulated SHA-256 for extracted URLs/payloads
        for url in extracted_urls:
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            iocs['attachment_hashes'].append({
                'artifact_type': 'TARGET_URL_HASH',
                'raw_value': url,
                'sha256': url_hash
            })
            
        for att in email_raw_data.get('attachments', []):
            att_name = att.get('filename', 'payload.bin')
            # real payload hash when we have it (IMAP / .eml parse); else fall back
            # to hashing the filename so the field is never empty.
            real_hash = att.get('sha256')
            iocs['attachment_hashes'].append({
                'artifact_type': 'ATTACHMENT_PAYLOAD',
                'filename': att_name,
                'sha256': real_hash or hashlib.sha256(att_name.encode()).hexdigest(),
                'hash_source': 'file_content' if real_hash else 'filename_only',
            })

        # MITRE ATT&CK Mappings
        mitre_tactics = [
            {'tactic_id': 'T1566.002', 'name': 'Phishing: Spearphishing Link', 'phase': 'Initial Access'},
            {'tactic_id': 'T1036.007', 'name': 'Masquerading: Double File Extension / Homoglyph Brand Impersonation', 'phase': 'Defense Evasion'},
            {'tactic_id': 'T1204.001', 'name': 'User Execution: Malicious Link', 'phase': 'Execution'}
        ]

        # Actionable SOC & Law Enforcement Containment Playbook
        recommended_actions = [
            {
                'priority': 'CRITICAL',
                'step': 'Domain Blacklisting & Sinkholing',
                'details': f"Submit '{domain}' and associated hostnames to DNS filter / firewall perimeter blocklists."
            },
            {
                'priority': 'CRITICAL',
                'step': 'Credential Invalidation & Active Session Revocation',
                'details': 'Force-terminate active sessions and prompt MFA reset for any user who interacted with the target URLs.'
            },
            {
                'priority': 'HIGH',
                'step': 'Mail Gateway Quarantine & Purge',
                'details': f"Run global tenant search query for sender '{sender}' and subject pattern '{subject}' to purge matching deliveries."
            },
            {
                'priority': 'HIGH',
                'step': 'Report to Registrar & National Cybercrime Portal',
                'details': f"File abuse takedown notice with registrar for domain '{domain}' and submit this formal dossier to Cybercrime authorities."
            }
        ]

        # Markdown formatted report for easy export / print
        markdown_dossier = f"""# OFFICIAL CYBERCRIME INCIDENT FORENSIC REPORT
**Incident Reference:** `{incident_id}`
**Classification:** `RESTRICTED / LAW ENFORCEMENT & SOC DOSSIER`
**Report Generated:** `{timestamp_str}`
**Threat Severity:** `{threat_level}` (Composite Risk Score: **{risk_score}/100**)

---

### 1. EXECUTIVE SUMMARY & VERDICT
- **Final Verdict:** **{verdict_label}**
- **Primary Attack Vector:** Social Engineering & Brand Impersonation Phishing
- **Targeted Organization/Brand:** {detected_brand.upper() if detected_brand else 'Unspecified Public'}
- **Target Recipient / Victim Mailbox:** `{email_raw_data.get('recipient', 'victim_inbox@domain.com')}`
- **Automated Defensive Action Taken:** `QUARANTINE_ISOLATED & BLOCKED`

---

### 2. ATTACK ATTRIBUTION & HEADER FORENSICS
- **Sender Display Name:** `{analysis_result.get('display_name', 'N/A')}`
- **Originating Sender Address:** `{sender}`
- **Sender Base Domain:** `{domain}`
- **Subject Line:** `{subject}`
- **SPF Authentication:** `{email_raw_data.get('spf_status', 'UNKNOWN')}`
- **DKIM Cryptographic Status:** `{email_raw_data.get('dkim_status', 'UNKNOWN')}`
- **DMARC Enforcement:** `{email_raw_data.get('dmarc_status', 'UNKNOWN')}`

---

### 3. FORENSIC EVIDENCE & FIRED THREAT INDICATORS
Total Indicators Fired: **{len(indicators)}**

| Indicator Code | Severity | Weight | Description |
| :--- | :--- | :--- | :--- |
"""
        for ind in indicators:
            markdown_dossier += f"| `{ind.get('type')}` | **{ind.get('severity')}** | +{ind.get('weight')} | {ind.get('detail')} |\n"

        markdown_dossier += f"""
---

### 4. INDICATORS OF COMPROMISE (IoCs)
- **Malicious Domain(s):** {', '.join([f'`{d}`' for d in iocs['malicious_domains']]) if iocs['malicious_domains'] else 'None'}
- **Extracted Phishing Link(s):**
"""
        for u in extracted_urls:
            markdown_dossier += f"  - `{u}`\n"

        markdown_dossier += """
- **Cryptographic Hashes (SHA-256):**
"""
        for h in iocs['attachment_hashes']:
            markdown_dossier += f"  - `{h.get('sha256')}` ({h.get('artifact_type')}: {h.get('raw_value', h.get('filename'))})\n"

        markdown_dossier += """
---

### 5. MITRE ATT&CK MATRIX MAPPING
"""
        for m in mitre_tactics:
            markdown_dossier += f"- **[{m['tactic_id']}]** {m['name']} (*{m['phase']}*)\n"

        markdown_dossier += """
---

### 6. MANDATORY CONTAINMENT PLAYBOOK
"""
        for act in recommended_actions:
            markdown_dossier += f"- **[{act['priority']}] {act['step']}**: {act['details']}\n"

        markdown_dossier += """
---
*Report automatically compiled and signed by PhishGuard AI Security Forensics Engine.*
"""

        # STIX 2.1 threat-intel bundle (structural, offline)
        try:
            from stix_builder import build_bundle
            stix_bundle = build_bundle(
                {**analysis_result, 'mitre_tactics': mitre_tactics}, email_raw_data, incident_id
            )
        except Exception:
            stix_bundle = None

        return {
            'incident_id': incident_id,
            'timestamp': timestamp_str,
            'threat_level': threat_level,
            'risk_score': risk_score,
            'verdict_label': verdict_label,
            'detected_brand': detected_brand,
            'iocs': iocs,
            'mitre_tactics': mitre_tactics,
            'recommended_actions': recommended_actions,
            'markdown_dossier': markdown_dossier,
            'stix_bundle': stix_bundle,
        }
