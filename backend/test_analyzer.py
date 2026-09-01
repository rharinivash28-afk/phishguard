"""Zero-dependency regression tests for the phishing analyzer.

Run directly:  python test_analyzer.py
(pytest also picks it up if installed, but it isn't required.)
"""
from analyzer import PhishingInvestigationEngine
from test_samples import SAMPLE_EMAILS

engine = PhishingInvestigationEngine()

# Domains a real user legitimately receives mail from. None of these may raise a
# brand-impersonation / typosquat indicator. "jira.techcorp.io" is the regression
# case: "jira" is Levenshtein-2 from the old 3-letter brand "irs".
LEGIT_DOMAINS = [
    "jira.techcorp.io", "confluence.techcorp.io", "github.com", "gitlab.com",
    "slack.com", "zoom.us", "notion.so", "figma.com", "asana.com",
    "calendly.com", "hubspot.com", "salesforce.com", "atlassian.net",
    "api.stripe.com", "aws.amazon.com", "dns.google", "mail.google.com",
    "accounts.google.com", "outlook.office365.com", "login.microsoftonline.com",
    "teams.microsoft.com", "support.zendesk.com", "app.datadoghq.com",
    "sentry.io", "pagerduty.com", "vpn.corp.net", "crm.company.io",
]

# Domains that must still be flagged as brand impersonation.
TYPOSQUAT_DOMAINS = [
    "paypa1-login.com", "m1crosoft-auth.net", "netfl1x-billing.co",
    "docus1gn-sign.com", "app1e-id.com", "arnazon-security.com",
    "g00gle-verify.com", "microsofft-support.com", "faceb00k-login.net",
    "paypai.com", "1inkedin.com", "dropb0x-share.com", "coinbaze.com",
]

# id -> (verdict, minimum risk score) the bundled samples must produce.
EXPECTED_SAMPLES = {
    "sample_ps02_paypal":     ("PHISHING_ATTACK", 85),
    "sample_m365_spoof":      ("PHISHING_ATTACK", 85),
    "sample_netflix_billing": ("PHISHING_ATTACK", 85),
    "sample_docusign_macro":  ("PHISHING_ATTACK", 85),
    "sample_legit_google":    ("LEGITIMATE", 0),
    "sample_legit_work":      ("LEGITIMATE", 0),
}

_BRAND_INDICATOR_TYPES = {"BRAND_TYPOSQUATTING_HOMOGLYPH", "TYPOSQUATTING_KEYWORD", "DISPLAY_NAME_SPOOFING"}


def _brand_flags(domain):
    return [i for i in engine.analyze_domain(domain)["indicators"]
            if i["type"] in _BRAND_INDICATOR_TYPES]


def test_legit_domains_have_no_brand_flag():
    offenders = {d: [i["name"] for i in _brand_flags(d)] for d in LEGIT_DOMAINS if _brand_flags(d)}
    assert not offenders, f"false-positive brand flags: {offenders}"


def test_typosquats_still_caught():
    missed = [d for d in TYPOSQUAT_DOMAINS if not _brand_flags(d)]
    assert not missed, f"typosquats no longer detected: {missed}"


def test_legit_sample_work_email_is_not_phishing():
    sample = next(s for s in SAMPLE_EMAILS if s["id"] == "sample_legit_work")
    result = engine.investigate(sample)
    assert result["verdict"] == "LEGITIMATE", result
    assert result["risk_score"] < 35, result["risk_score"]


def test_all_samples_match_expected_verdict():
    for sample in SAMPLE_EMAILS:
        want_verdict, want_min = EXPECTED_SAMPLES[sample["id"]]
        got = engine.investigate(sample)
        assert got["verdict"] == want_verdict, f"{sample['id']}: {got['verdict']} != {want_verdict}"
        if want_verdict == "PHISHING_ATTACK":
            assert got["risk_score"] >= want_min, f"{sample['id']}: score {got['risk_score']} < {want_min}"


def test_display_name_spoof_word_boundary():
    # "Groups" contains "ups" but is not UPS impersonation
    benign = engine.analyze_domain("techcorp.io", display_name="TechCorp Groups Team")
    assert not [i for i in benign["indicators"] if i["type"] == "DISPLAY_NAME_SPOOFING"], benign["indicators"]
    # an actual claim of being PayPal from an unrelated domain still fires
    spoof = engine.analyze_domain("mailer-xyz.com", display_name="PayPal Service")
    assert [i for i in spoof["indicators"] if i["type"] == "DISPLAY_NAME_SPOOFING"], spoof["indicators"]


def test_homoglyph_fold_is_stable():
    from analyzer import normalize_homoglyphs
    # bidirectional maps used to cancel out ('0'->'o' then 'o'->'0'); folding must be idempotent
    assert normalize_homoglyphs("g00gle") == normalize_homoglyphs("google")
    assert normalize_homoglyphs("paypa1") == normalize_homoglyphs("paypal")
    assert normalize_homoglyphs("arnazon") == normalize_homoglyphs("amazon")


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
