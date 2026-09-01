"""Detection-improvement tests: HTML bodies, real attachment hashes, and the
optional Safe Browsing / NVIDIA paths staying inert without keys.

Zero-dependency (uses only stdlib + analyzer/gmail_service). Run directly:
    python test_detection.py
"""
import hashlib
import os

# make sure the optional integrations are OFF for this test run
os.environ.pop("GOOGLE_SAFE_BROWSING_KEY", None)
os.environ.pop("NVIDIA_API_KEY", None)

from analyzer import PhishingInvestigationEngine  # noqa: E402
from gmail_service import parse_eml_bytes  # noqa: E402

engine = PhishingInvestigationEngine()

HTML_EML = b"""From: Bank <alerts@evil-phish.example>
Subject: Urgent: verify your account
Content-Type: text/html; charset=utf-8

<html><body>
<style>.x{color:red}</style>
<p>Your account will be suspended within 24 hours.</p>
<a href="http://evil-phish.example/harvest">https://secure.yourbank.com/login</a>
<script>steal()</script>
</body></html>
"""


def test_html_body_extracted_and_anchor_mismatch_fires():
    parsed = parse_eml_bytes(HTML_EML)
    assert "suspended within 24 hours" in parsed["body"]
    assert "<script>" not in parsed["body"] and "color:red" not in parsed["body"]
    urls = {u["url"] for u in parsed["urls"]}
    assert "http://evil-phish.example/harvest" in urls
    result = engine.investigate(parsed)
    assert any(i["type"] == "ANCHOR_TEXT_MISMATCH" for i in result["indicators"]), result["indicators"]


def test_real_attachment_hash():
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    m = MIMEMultipart()
    m["From"] = "x@y.com"
    m["Subject"] = "invoice"
    m.attach(MIMEText("see attached", "plain"))
    payload = b"MZ\x90\x00 fake executable payload"
    a = MIMEApplication(payload, Name="invoice.pdf.exe")
    a["Content-Disposition"] = 'attachment; filename="invoice.pdf.exe"'
    m.attach(a)

    parsed = parse_eml_bytes(m.as_bytes())
    att = parsed["attachments"][0]
    assert att["sha256"] == hashlib.sha256(payload).hexdigest()
    assert att["sha256"] != hashlib.sha256(b"invoice.pdf.exe").hexdigest()


def test_safe_browsing_and_llm_are_inert_without_keys(monkeypatch=None):
    # threat_intel.check_urls must not attempt a network call with no key
    import threat_intel

    called = {"n": 0}
    orig_post = threat_intel.requests.post

    def _boom(*a, **k):
        called["n"] += 1
        return orig_post(*a, **k)

    threat_intel.requests.post = _boom
    try:
        assert threat_intel.check_urls(["http://example.com"]) == {}
        assert called["n"] == 0
    finally:
        threat_intel.requests.post = orig_post

    import llm_review

    assert llm_review.is_enabled() is False
    assert llm_review.llm_verdict({"subject": "x", "body": "y"}) is None


def test_expanded_brands_no_false_positives():
    engine_local = PhishingInvestigationEngine()
    legit = [
        "open.spotify.com", "discord.com", "twitch.tv", "www.ebay.com",
        "www.uber.com", "www.airbnb.com", "www.irs.gov", "account.venmo.com",
        "www.capitalone.com", "store.steampowered.com",
    ]
    for d in legit:
        inds = engine_local.analyze_domain(d)["indicators"]
        bad = [i for i in inds if i["type"] in
               {"BRAND_TYPOSQUATTING_HOMOGLYPH", "TYPOSQUATTING_KEYWORD", "DISPLAY_NAME_SPOOFING"}]
        assert not bad, f"{d} falsely flagged: {[i['name'] for i in bad]}"


def test_new_brand_typosquat_still_caught():
    for d in ["venrno-pay.com", "sp0tify-premium.net", "discorcl-nitro.com"]:
        inds = engine.analyze_domain(d)["indicators"]
        assert any("Typosquat" in i["name"] or "Lookalike" in i["name"] for i in inds), d


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
