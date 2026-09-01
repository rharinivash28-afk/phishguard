import re
import urllib.parse
from typing import List, Dict, Any, Optional

POPULAR_BRANDS = [
    'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'chase',
    'bank of america', 'wells fargo', 'dropbox', 'docusign', 'facebook',
    'instagram', 'linkedin', 'adobe', 'stripe', 'zoom', 'coinbase', 'binance',
    'citibank', 'american express', 'barclays', 'fedex', 'dhl', 'ups'
]

# A benign word is roughly as close to a 3-letter brand ("ups", "dhl") as a
# genuine typosquat is, so the fuzzy-match budget has to scale with brand length.
# Below this length we only trust an exact / homoglyph-normalized match.
def _typo_edit_budget(brand: str) -> int:
    n = len(brand)
    if n <= 4:
        return 0
    if n <= 6:
        return 1
    return 2

# Canonical fold: every look-alike collapses to ONE representative form, so both
# the suspect token and the real brand can be reduced to the same string. The map
# must be one-directional (no 'a'->'b' *and* 'b'->'a') or the passes cancel out.
# Multi-character rules are applied first (see normalize_homoglyphs).
HOMOGLYPH_FOLD = {
    'vv': 'w',
    'rn': 'm',
    '1': 'l', 'i': 'l', '|': 'l',
    '0': 'o',
    '3': 'e',
    '5': 's', '$': 's',
    '8': 'b',
    '@': 'a', '4': 'a',
    '7': 't',
}

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.cam',
    '.work', '.click', '.live', '.monster', '.rest', '.quest', '.bid', '.racing'
}

SUSPICIOUS_SUBDOMAINS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'security', 'secure', 'portal',
    'auth', 'update', 'billing', 'support', 'service', 'validation', 'confirm',
    'suspended', 'unlock', 'banking'
]

URGENCY_PATTERNS = [
    (r'(account|access)\s+(will\s+be\s+)?(suspended|terminated|locked|closed|disabled|deactivated)', 'High Urgency: Account Suspension Threat', 25),
    (r'(immediate|urgent|critical|prompt)\s+action\s+(required|needed)', 'High Urgency: Immediate Action Coercion', 20),
    (r'(within|in)\s+(24|48|12|2|1)\s+(hours|hrs|days|minutes|mins)', 'Artificial Time Pressure (Countdown Deadline)', 20),
    (r'(unauthorized|suspicious|unrecognized)\s+(activity|access|login|transaction|charge)', 'Fear-Inducing Security Alert Cue', 18),
    (r'(verify|confirm|validate|update)\s+your\s+(account|identity|details|billing|payment|password)', 'Credential/Identity Verification Trigger', 18),
    (r'(failure|fail)\s+to\s+(comply|respond|verify|update)\s+will\s+result', 'Coercive Penalty Language', 20),
    (r'(final\s+notice|last\s+warning|legal\s+action)', 'Extreme Urgency / Legal Intimidation', 22),
    (r'won\s+(\$|usd|euro|prize|lottery|crypto|bitcoin|reward)', 'Financial Temptation / Baiting', 15),
    (r'(wire\s+transfer|gift\s+card|bitcoin\s+wallet)', 'High-Risk Payment Method Request', 25)
]

DANGEROUS_EXTENSIONS = {
    '.exe': 'Windows Executable binary',
    '.scr': 'Windows ScreenSaver Executable',
    '.bat': 'Batch Script file',
    '.cmd': 'Command Script file',
    '.vbs': 'VBScript file',
    '.js': 'JavaScript Script file',
    '.hta': 'HTML Application file',
    '.iso': 'Disk Image Container',
    '.img': 'Disk Image Container',
    '.wsf': 'Windows Script File',
    '.ps1': 'PowerShell Script file',
    '.docm': 'Word Macro-Enabled Document',
    '.xlsm': 'Excel Macro-Enabled Spreadsheet',
    '.jar': 'Java Executable Archive'
}

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_homoglyphs(text: str) -> str:
    """Fold a string to its canonical look-alike form.

    Multi-character glyphs (``rn`` -> ``m``, ``vv`` -> ``w``) are substituted
    before the single-character rules so "arnazon" folds to "amazon" cleanly.
    """
    res = text.lower()
    for glyph, rep in sorted(HOMOGLYPH_FOLD.items(), key=lambda kv: -len(kv[0])):
        res = res.replace(glyph, rep)
    return res

def extract_domain(email_or_url: str) -> str:
    if not email_or_url:
        return ''
    if '@' in email_or_url:
        email_or_url = email_or_url.split('@')[-1].strip('>')
    if '://' in email_or_url:
        parsed = urllib.parse.urlparse(email_or_url)
        return parsed.netloc.split(':')[0]
    match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_or_url)
    return match.group(1).lower() if match else email_or_url.lower()

class PhishingInvestigationEngine:
    def __init__(self):
        pass

    def analyze_domain(self, domain: str, display_name: str = '') -> Dict[str, Any]:
        indicators = []
        domain_lower = domain.lower()
        score = 0
        detected_brand = None
        
        clean_domain_name = domain_lower.split('.')[0] if '.' in domain_lower else domain_lower
        domain_tokens = re.split(r'[-._]', clean_domain_name)
        
        for brand in POPULAR_BRANDS:
            brand_clean = brand.replace(' ', '')
            budget = _typo_edit_budget(brand_clean)
            brand_folded = normalize_homoglyphs(brand_clean)

            # Check full clean domain name or tokens
            for token in [clean_domain_name] + domain_tokens:
                if not token or token == brand_clean:
                    continue
                norm_token = normalize_homoglyphs(token)
                dist = levenshtein_distance(token, brand_clean)
                norm_dist = levenshtein_distance(norm_token, brand_folded)

                # A near-miss on the *raw* token only counts when the edit budget
                # (which scales with brand length) allows it. A homoglyph fold that
                # lands on (or one edit from) the brand — e.g. "paypa1" -> "paypal",
                # "arnazon" -> "amazon" — counts once the token isn't trivially short.
                fuzzy_hit = budget > 0 and dist <= budget
                homoglyph_hit = len(token) >= 5 and norm_dist <= (1 if len(brand_folded) >= 6 else 0)

                if fuzzy_hit or homoglyph_hit:
                    indicators.append({
                        'type': 'BRAND_TYPOSQUATTING_HOMOGLYPH',
                        'severity': 'CRITICAL',
                        'weight': 40,
                        'name': f'Brand Typosquatting & Homoglyph Attack ({brand.upper()})',
                        'detail': f"Domain token '{token}' in '{domain}' deceptively mimics official brand '{brand}' (Levenshtein Distance: {dist}, Homoglyph Substitution detected)."
                    })
                    score += 40
                    detected_brand = brand
                    break
                elif len(brand_clean) >= 5 and brand_clean in token:
                    indicators.append({
                        'type': 'TYPOSQUATTING_KEYWORD',
                        'severity': 'HIGH',
                        'weight': 25,
                        'name': f'Targeted Brand Lookalike ({brand.upper()})',
                        'detail': f"Domain '{domain}' chains official brand '{brand}' with suspicious sub-strings."
                    })
                    score += 25
                    detected_brand = brand
                    break
            if detected_brand:
                break

        for tld in SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                indicators.append({
                    'type': 'SUSPICIOUS_TLD',
                    'severity': 'MEDIUM',
                    'weight': 15,
                    'name': f'High-Risk Suspicious TLD ({tld})',
                    'detail': f"Domain uses '{tld}' which is frequently abused in automated phishing kits."
                })
                score += 15
                break

        if '-' in clean_domain_name:
            for kw in SUSPICIOUS_SUBDOMAINS_KEYWORDS:
                if kw in clean_domain_name:
                    indicators.append({
                        'type': 'DECEPTIVE_DOMAIN_STRUCTURE',
                        'severity': 'HIGH',
                        'weight': 20,
                        'name': f'Deceptive Keyword Chaining (-{kw})',
                        'detail': f"Domain uses deceptive hyphenated phrasing '{kw}' to mimic a legitimate login/verification portal."
                    })
                    score += 20
                    break

        if display_name:
            display_lower = display_name.lower()
            for brand in POPULAR_BRANDS:
                # whole-word match only: "UPS" must not fire on "groups"/"startups"
                claims_brand = re.search(rf'\b{re.escape(brand)}\b', display_lower) is not None
                if claims_brand and brand not in domain_lower:
                    indicators.append({
                        'type': 'DISPLAY_NAME_SPOOFING',
                        'severity': 'CRITICAL',
                        'weight': 35,
                        'name': f'Display Name Impersonation ({brand.upper()})',
                        'detail': f"Sender display name claims to be '{display_name}' but the actual sender domain is '{domain}'."
                    })
                    score += 35
                    if not detected_brand:
                        detected_brand = brand
                    break

        return {
            'domain': domain,
            'detected_brand': detected_brand,
            'domain_score': min(score, 50),
            'indicators': indicators
        }

    def analyze_urls(self, urls: List[Dict[str, str]]) -> Dict[str, Any]:
        indicators = []
        score = 0
        extracted_iocs = []

        for item in urls:
            raw_url = item.get('url', '')
            anchor_text = item.get('anchor', '')
            if not raw_url:
                continue

            extracted_iocs.append(raw_url)
            parsed = urllib.parse.urlparse(raw_url)
            netloc = parsed.netloc.lower()
            scheme = parsed.scheme.lower()
            path = parsed.path.lower()

            if scheme == 'http':
                indicators.append({
                    'type': 'INSECURE_PROTOCOL',
                    'severity': 'HIGH',
                    'weight': 20,
                    'name': 'Insecure HTTP Protocol on Authentication Target',
                    'detail': f"URL '{raw_url}' uses unencrypted HTTP rather than HTTPS for a credential/sensitive action."
                })
                score += 20

            if anchor_text and ('.' in anchor_text or 'http' in anchor_text):
                anchor_domain = extract_domain(anchor_text)
                href_domain = extract_domain(netloc)
                if anchor_domain and href_domain and anchor_domain != href_domain:
                    indicators.append({
                        'type': 'ANCHOR_TEXT_MISMATCH',
                        'severity': 'CRITICAL',
                        'weight': 35,
                        'name': 'Deceptive Link Text Masking',
                        'detail': f"Display text appears as '{anchor_text}' but actually redirects victims to '{raw_url}'."
                    })
                    score += 35

            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', netloc):
                indicators.append({
                    'type': 'RAW_IP_URL',
                    'severity': 'CRITICAL',
                    'weight': 30,
                    'name': 'Direct IP Address Hostname in Link',
                    'detail': f"URL points directly to raw IP address '{netloc}' bypassing domain reputation systems."
                })
                score += 30

            for kw in ['verify', 'login', 'signin', 'auth', 'update', 'account', 'suspended', 'session', 'confirm']:
                if kw in path or kw in netloc:
                    indicators.append({
                        'type': 'CREDENTIAL_HARVESTING_PATH',
                        'severity': 'HIGH',
                        'weight': 15,
                        'name': f'Credential Harvesting Target Endpoint (/{kw})',
                        'detail': f"URL path contains suspicious phishing kit keyword '{kw}'."
                    })
                    score += 15
                    break

            domain_res = self.analyze_domain(netloc)
            for ind in domain_res['indicators']:
                if not any(existing['name'] == ind['name'] for existing in indicators):
                    indicators.append(ind)
                    score += ind['weight']

        return {
            'url_score': min(score, 50),
            'indicators': indicators,
            'extracted_urls': extracted_iocs
        }

    def analyze_urgency_and_nlp(self, text: str) -> Dict[str, Any]:
        indicators = []
        score = 0
        fired_keywords = []

        if not text:
            return {'urgency_score': 0, 'indicators': [], 'fired_keywords': []}

        for pattern, name, weight in URGENCY_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_snippet = match.group(0)
                fired_keywords.append(matched_snippet)
                indicators.append({
                    'type': 'URGENCY_NLP_TRIGGER',
                    'severity': 'HIGH' if weight >= 20 else 'MEDIUM',
                    'weight': weight,
                    'name': name,
                    'detail': f"Detected coercive psychological trigger: '{matched_snippet}'."
                })
                score += weight

        return {
            'urgency_score': min(score, 45),
            'indicators': indicators,
            'fired_keywords': list(set(fired_keywords))
        }

    def analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        indicators = []
        score = 0

        for att in attachments:
            name = att.get('filename', '').lower()
            
            parts = name.split('.')
            if len(parts) > 2:
                for ext in ['.exe', '.vbs', '.bat', '.scr', '.js', '.hta', '.cmd']:
                    if name.endswith(ext):
                        indicators.append({
                            'type': 'DOUBLE_EXTENSION_PAYLOAD',
                            'severity': 'CRITICAL',
                            'weight': 40,
                            'name': 'Double Extension Masquerading Attachment',
                            'detail': f"Attachment '{name}' masks executable file under document guise."
                        })
                        score += 40
                        break

            for ext, desc in DANGEROUS_EXTENSIONS.items():
                if name.endswith(ext):
                    indicators.append({
                        'type': 'MALICIOUS_ATTACHMENT_TYPE',
                        'severity': 'CRITICAL',
                        'weight': 35,
                        'name': f'High-Risk Attachment ({desc})',
                        'detail': f"Attachment '{name}' is an executable or macro-enabled weaponized payload."
                    })
                    score += 35
                    break

        return {
            'attachment_score': min(score, 50),
            'indicators': indicators
        }

    def investigate(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        sender_address = email_data.get('sender_address', '')
        display_name = email_data.get('display_name', '')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        urls = email_data.get('urls', [])
        attachments = email_data.get('attachments', [])
        spf_status = email_data.get('spf_status', 'UNKNOWN')
        dkim_status = email_data.get('dkim_status', 'UNKNOWN')
        dmarc_status = email_data.get('dmarc_status', 'UNKNOWN')

        if not urls and body:
            extracted_raw = re.findall(r'https?://[^\s<>"\'\)]+', body)
            urls = [{'url': u, 'anchor': ''} for u in extracted_raw]

        domain = extract_domain(sender_address)

        domain_analysis = self.analyze_domain(domain, display_name)
        url_analysis = self.analyze_urls(urls)
        nlp_analysis = self.analyze_urgency_and_nlp(f"{subject} {body}")
        attachment_analysis = self.analyze_attachments(attachments)

        header_indicators = []
        header_score = 0
        if spf_status in ['FAIL', 'SOFTFAIL']:
            header_indicators.append({
                'type': 'SPF_VALIDATION_FAILED',
                'severity': 'HIGH',
                'weight': 20,
                'name': f'SPF Authentication Failed ({spf_status})',
                'detail': f"Sending server is not authorized by '{domain}' SPF record."
            })
            header_score += 20

        if dkim_status == 'FAIL':
            header_indicators.append({
                'type': 'DKIM_VALIDATION_FAILED',
                'severity': 'HIGH',
                'weight': 20,
                'name': 'DKIM Cryptographic Signature Invalid',
                'detail': 'Email message body or headers were altered in transit.'
            })
            header_score += 20

        if dmarc_status == 'FAIL':
            header_indicators.append({
                'type': 'DMARC_POLICY_REJECT',
                'severity': 'HIGH',
                'weight': 25,
                'name': 'DMARC Alignment Check Failed',
                'detail': 'Sender domain failed both SPF/DKIM alignment checks.'
            })
            header_score += 25

        all_indicators = (
            domain_analysis['indicators'] +
            url_analysis['indicators'] +
            nlp_analysis['indicators'] +
            attachment_analysis['indicators'] +
            header_indicators
        )

        unique_indicators = []
        seen_names = set()
        for ind in all_indicators:
            if ind['name'] not in seen_names:
                seen_names.add(ind['name'])
                unique_indicators.append(ind)

        raw_composite = (
            domain_analysis['domain_score'] * 0.30 +
            url_analysis['url_score'] * 0.35 +
            nlp_analysis['urgency_score'] * 0.20 +
            attachment_analysis['attachment_score'] * 0.25 +
            min(header_score, 40) * 0.20
        )

        critical_count = sum(1 for i in unique_indicators if i['severity'] == 'CRITICAL')
        high_count = sum(1 for i in unique_indicators if i['severity'] == 'HIGH')

        if critical_count >= 2:
            raw_composite = max(raw_composite, 94.0)
        elif critical_count == 1 and high_count >= 1:
            raw_composite = max(raw_composite, 86.0)
        elif critical_count == 1:
            raw_composite = max(raw_composite, 75.0)
        elif high_count >= 2:
            raw_composite = max(raw_composite, 68.0)

        risk_score = round(min(max(raw_composite, 0.0), 99.8), 1)

        if risk_score >= 70:
            verdict = 'PHISHING_ATTACK'
            verdict_label = 'Confirmed Phishing / Malicious'
            threat_level = 'CRITICAL' if risk_score >= 85 else 'HIGH'
            action_recommended = 'IMMEDIATE_QUARANTINE_AND_INCIDENT_REPORT'
        elif risk_score >= 35:
            verdict = 'SUSPICIOUS'
            verdict_label = 'Suspicious / Untrusted'
            threat_level = 'MEDIUM'
            action_recommended = 'WARN_USER_AND_SANDBOX'
        else:
            verdict = 'LEGITIMATE'
            verdict_label = 'Legitimate / Safe'
            threat_level = 'LOW'
            action_recommended = 'DELIVER_TO_INBOX'

        detected_brand_final = domain_analysis.get('detected_brand')

        return {
            'email_id': email_data.get('id', 'msg_' + str(abs(hash(sender_address + subject)))),
            'sender_address': sender_address,
            'display_name': display_name,
            'domain': domain,
            'subject': subject,
            'risk_score': risk_score,
            'verdict': verdict,
            'verdict_label': verdict_label,
            'threat_level': threat_level,
            'action_recommended': action_recommended,
            'detected_brand': detected_brand_final,
            'indicators': unique_indicators,
            'indicators_count': len(unique_indicators),
            'critical_indicators_count': critical_count,
            'fired_keywords': nlp_analysis.get('fired_keywords', []),
            'extracted_urls': url_analysis.get('extracted_urls', []),
            'score_breakdown': {
                'domain_reputation': domain_analysis['domain_score'],
                'url_inspection': url_analysis['url_score'],
                'urgency_nlp': nlp_analysis['urgency_score'],
                'attachments': attachment_analysis['attachment_score'],
                'header_auth': min(header_score, 40)
            }
        }
