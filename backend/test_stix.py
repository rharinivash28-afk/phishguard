"""STIX 2.1 bundle structural validation. Zero deps (no stix2 lib).

Run: python test_stix.py
"""
import json
import re

from analyzer import PhishingInvestigationEngine
from report_generator import CybercrimeIncidentReportGenerator
from stix_builder import build_bundle
from test_samples import SAMPLE_EMAILS

_ID_RE = re.compile(
    r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_engine = PhishingInvestigationEngine()


def _bundle_for(sample_id):
    s = next(x for x in SAMPLE_EMAILS if x["id"] == sample_id)
    analysis = _engine.investigate(s)
    return build_bundle(analysis, s, "CC-INC-TEST-ABC123"), analysis, s


def test_bundle_shape():
    b, _, _ = _bundle_for("sample_ps02_paypal")
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--")
    assert isinstance(b["objects"], list) and len(b["objects"]) >= 5


def test_every_object_id_and_spec_version():
    b, _, _ = _bundle_for("sample_docusign_macro")
    for o in b["objects"]:
        assert "type" in o and "id" in o, o
        assert _ID_RE.match(o["id"]), f"bad id: {o['id']}"
        # SDOs carry spec_version; SCOs (email-addr/file/email-message) also do in 2.1
        assert o.get("spec_version") == "2.1", f"{o['type']} missing spec_version"


def test_indicators_have_valid_patterns():
    b, analysis, _ = _bundle_for("sample_ps02_paypal")
    indicators = [o for o in b["objects"] if o["type"] == "indicator"]
    assert indicators, "no indicators produced for a phishing sample"
    for ind in indicators:
        assert ind["pattern_type"] == "stix"
        assert ind["pattern"].startswith("[") and ind["pattern"].endswith("]")
        assert "malicious-activity" in ind["indicator_types"]


def test_relationships_reference_real_objects():
    b, _, _ = _bundle_for("sample_docusign_macro")
    ids = {o["id"] for o in b["objects"]}
    rels = [o for o in b["objects"] if o["type"] == "relationship"]
    assert rels, "expected indicator->attack-pattern relationships"
    for r in rels:
        assert r["source_ref"] in ids, r["source_ref"]
        assert r["target_ref"] in ids, r["target_ref"]
        assert r["relationship_type"] == "indicates"


def test_attachment_hash_flows_into_file_sco():
    # docusign sample has a .pdf.exe attachment; give it a real sha256
    s = dict(next(x for x in SAMPLE_EMAILS if x["id"] == "sample_docusign_macro"))
    s["attachments"] = [{"filename": "x.pdf.exe", "size": 10, "sha256": "a" * 64}]
    b = build_bundle(_engine.investigate(s), s, "CC-INC-HASH")
    files = [o for o in b["objects"] if o["type"] == "file"]
    assert files and files[0]["hashes"]["SHA-256"] == "a" * 64


def test_deterministic():
    b1, _, _ = _bundle_for("sample_ps02_paypal")
    b2, _, _ = _bundle_for("sample_ps02_paypal")
    assert b1["id"] == b2["id"]
    assert [o["id"] for o in b1["objects"]] == [o["id"] for o in b2["objects"]]


def test_json_serializable():
    b, _, _ = _bundle_for("sample_legit_google")
    json.loads(json.dumps(b))


def test_report_generator_embeds_bundle():
    s = next(x for x in SAMPLE_EMAILS if x["id"] == "sample_ps02_paypal")
    a = _engine.investigate(s)
    r = CybercrimeIncidentReportGenerator.generate_report(a, s)
    assert r["stix_bundle"] and r["stix_bundle"]["type"] == "bundle"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}\n      {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
