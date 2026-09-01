"""STIX 2.1 threat-intelligence bundle from a PhishGuard analysis.

Hand-built to the STIX 2.1 spec (no `stix2` dependency). Object ids are
deterministic (uuid5 keyed off the incident id + object role) so re-exporting the
same incident yields byte-identical ids — friendly to diffing and dedup.
"""
import datetime
import uuid
from typing import Any, Dict, List

# stable namespace so uuid5 output is reproducible across runs / machines
_NS = uuid.UUID("9b5f2e94-6d3a-4c1b-8e77-1f0a2c4d6e88")
_SPEC = "2.1"

_MITRE_URLS = {
    "T1566.002": "https://attack.mitre.org/techniques/T1566/002/",
    "T1036.007": "https://attack.mitre.org/techniques/T1036/007/",
    "T1204.001": "https://attack.mitre.org/techniques/T1204/001/",
}


def _sid(kind: str, incident_id: str, role: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, f'{incident_id}:{kind}:{role}')}"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _escape(v: str) -> str:
    return (v or "").replace("\\", "\\\\").replace("'", "\\'")


def build_bundle(analysis: Dict[str, Any], email_data: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
    now = _now_iso()
    objects: List[Dict[str, Any]] = []

    # --- creator identity ---------------------------------------------------
    identity_id = _sid("identity", incident_id, "creator")
    objects.append({
        "type": "identity",
        "spec_version": _SPEC,
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "PhishGuard AI — Enterprise Inbox Sentinel",
        "identity_class": "system",
        "sectors": ["technology"],
    })

    def _common(created_id: str) -> Dict[str, Any]:
        return {
            "spec_version": _SPEC,
            "id": created_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
        }

    domain = analysis.get("domain") or ""
    urls = [u for u in (analysis.get("extracted_urls") or []) if u]
    sender = analysis.get("sender_address") or email_data.get("sender_address") or ""
    risk = analysis.get("risk_score", 0)
    is_malicious = risk >= 50

    indicator_ids: List[str] = []

    # --- indicator: sender domain ----------------------------------------
    if domain and is_malicious:
        ind_id = _sid("indicator", incident_id, "domain")
        objects.append({
            "type": "indicator",
            **_common(ind_id),
            "name": f"Phishing sender domain {domain}",
            "description": analysis.get("verdict_label", "Suspicious sender domain"),
            "indicator_types": ["malicious-activity"],
            "pattern": f"[domain-name:value = '{_escape(domain)}']",
            "pattern_type": "stix",
            "pattern_version": _SPEC,
            "valid_from": now,
        })
        indicator_ids.append(ind_id)

    # --- indicators: each extracted URL --------------------------------
    for i, url in enumerate(urls):
        ind_id = _sid("indicator", incident_id, f"url-{i}")
        objects.append({
            "type": "indicator",
            **_common(ind_id),
            "name": f"Phishing URL ({url[:60]})",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[url:value = '{_escape(url)}']",
            "pattern_type": "stix",
            "pattern_version": _SPEC,
            "valid_from": now,
        })
        indicator_ids.append(ind_id)

    # --- observed-data + email SCOs -----------------------------------
    email_addr_id = f"email-addr--{uuid.uuid5(_NS, f'{incident_id}:from:{sender}')}"
    email_msg_id = f"email-message--{uuid.uuid5(_NS, f'{incident_id}:message')}"
    scos: List[Dict[str, Any]] = [
        {"type": "email-addr", "spec_version": _SPEC, "id": email_addr_id, "value": sender or "unknown@unknown"},
        {
            "type": "email-message",
            "spec_version": _SPEC,
            "id": email_msg_id,
            "is_multipart": bool(email_data.get("attachments")),
            "from_ref": email_addr_id,
            "subject": (analysis.get("subject") or email_data.get("subject") or "")[:998],
        },
    ]

    # attachment file SCOs (real SHA-256 when the parser captured it)
    for j, att in enumerate(email_data.get("attachments") or []):
        fname = att.get("filename", "") or f"attachment-{j}"
        fid = f"file--{uuid.uuid5(_NS, f'{incident_id}:file:{j}:{fname}')}"
        f_obj = {"type": "file", "spec_version": _SPEC, "id": fid, "name": fname}
        if att.get("sha256"):
            f_obj["hashes"] = {"SHA-256": att["sha256"]}
        scos.append(f_obj)

    od_id = _sid("observed-data", incident_id, "email")
    objects.append({
        "type": "observed-data",
        **_common(od_id),
        "first_observed": now,
        "last_observed": now,
        "number_observed": 1,
        "object_refs": [s["id"] for s in scos],
    })
    objects.extend(scos)

    # --- attack-pattern objects (MITRE ATT&CK) ------------------------
    attack_ids: List[str] = []
    for m in analysis.get("mitre_tactics", []) or _default_mitre():
        tid = m.get("tactic_id", "")
        ap_id = _sid("attack-pattern", incident_id, tid or m.get("name", ""))
        objects.append({
            "type": "attack-pattern",
            **_common(ap_id),
            "name": m.get("name", "Phishing"),
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": _MITRE_URLS.get(tid, f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
            }] if tid else [],
        })
        attack_ids.append(ap_id)

    # --- relationships: indicator --indicates--> attack-pattern -------
    for ind_id in indicator_ids:
        for ap_id in attack_ids:
            rel_id = _sid("relationship", incident_id, f"{ind_id}->{ap_id}")
            objects.append({
                "type": "relationship",
                **_common(rel_id),
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": ap_id,
            })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NS, f'{incident_id}:bundle')}",
        "objects": objects,
    }


def _default_mitre() -> List[Dict[str, str]]:
    return [
        {"tactic_id": "T1566.002", "name": "Phishing: Spearphishing Link", "phase": "Initial Access"},
        {"tactic_id": "T1204.001", "name": "User Execution: Malicious Link", "phase": "Execution"},
    ]
