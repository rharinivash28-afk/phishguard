"""Detection-accuracy regression corpus.

A broad set of phishing + legitimate emails with expected verdict bands. Guards
against both false negatives (real phish scored < 70) and false positives (real
mail scored >= 35). Pure engine — no DB, no network. Run: python test_accuracy.py
"""
import os

os.environ.pop("GOOGLE_SAFE_BROWSING_KEY", None)
os.environ.pop("NVIDIA_API_KEY", None)

from analyzer import PhishingInvestigationEngine  # noqa: E402

E = PhishingInvestigationEngine()


def _email(**kw):
    for k, d in [
        ("display_name", ""), ("spf_status", "UNKNOWN"), ("dkim_status", "UNKNOWN"),
        ("dmarc_status", "UNKNOWN"), ("urls", []), ("attachments", []), ("body", ""),
    ]:
        kw.setdefault(k, d)
    return kw


# (name, email, min_score or None, max_score or None)
PHISH = [
    ("paypal homoglyph + urgency", _email(
        sender_address="service@paypa1-secure.com", display_name="PayPal",
        subject="Your account has been limited - action required within 24 hours",
        body="Confirm your identity now or your account will be permanently suspended: http://paypa1-secure.com/verify",
        urls=[{"url": "http://paypa1-secure.com/verify", "anchor": "Verify"}],
        spf_status="FAIL", dkim_status="FAIL", dmarc_status="FAIL"), 70),
    ("microsoft typosquat password expiry", _email(
        sender_address="no-reply@microsft-online.com", display_name="Microsoft 365",
        subject="Your password expires today - re-authenticate now",
        body="Your password will expire in 2 hours. Verify here: https://microsft-online.com/login",
        urls=[{"url": "https://microsft-online.com/login", "anchor": "Keep my password"}],
        spf_status="SOFTFAIL", dkim_status="FAIL", dmarc_status="FAIL"), 70),
    ("raw-IP bank credential harvest", _email(
        sender_address="alerts@secure-chase.com", display_name="Chase Bank",
        subject="Suspicious sign-in blocked - verify it was you",
        body="Verify your account: http://192.168.44.9/chase/login",
        urls=[{"url": "http://192.168.44.9/chase/login", "anchor": "This was me"}],
        spf_status="FAIL", dkim_status="FAIL", dmarc_status="FAIL"), 70),
    ("DHL fee scam, suspicious TLD, http, auth fail", _email(
        sender_address="delivery@dhl-express-tracking.info", display_name="DHL Express",
        subject="Your parcel is on hold - customs fee required",
        body="Pay here to release your package: http://dhl-express-tracking.info/pay",
        urls=[{"url": "http://dhl-express-tracking.info/pay", "anchor": "Pay customs fee"}],
        spf_status="FAIL", dmarc_status="FAIL"), 70),
    ("docusign double-extension attachment", _email(
        sender_address="dse@docu-sign-agreements.com", display_name="DocuSign",
        subject="Completed: Please DocuSign this document",
        body="Open the attachment and enable macros to view.",
        attachments=[{"filename": "Contract_Final.pdf.exe", "size": 284000}],
        spf_status="FAIL", dmarc_status="FAIL"), 70),
    ("display-name spoof, homoglyph domain", _email(
        sender_address="security@g00gle-accounts.com", display_name="Google",
        subject="Critical security alert - review activity now",
        body="A new device signed in. Secure your account: http://g00gle-accounts.com/secure",
        urls=[{"url": "http://g00gle-accounts.com/secure", "anchor": "Secure account"}],
        spf_status="FAIL", dkim_status="FAIL", dmarc_status="FAIL"), 70),
    ("deceptive anchor text (HTML phish)", _email(
        sender_address="alerts@secure-bank-online.com", display_name="Wells Fargo Online",
        subject="Action needed: confirm recent transaction",
        body="Please review: https://www.wellsfargo.com/confirm",
        urls=[{"url": "http://secure-bank-online.com/harvest", "anchor": "https://www.wellsfargo.com/confirm"}],
        spf_status="FAIL", dkim_status="FAIL", dmarc_status="FAIL"), 70),
    ("BEC gift-card, text only, auth pass", _email(
        sender_address="m.johnson.finance@outlook.com",
        display_name="Michael Johnson - Finance Director",
        subject="Are you at your desk?",
        body="I need you to purchase four $500 Amazon gift cards and email me the redemption codes. "
             "I'll approve the reimbursement. Do not call, I'm in meetings.",
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS"), 70),
    ("lookalike subdomain of real brand", _email(
        sender_address="alert@login.microsoftonline.com.secure-verify.io", display_name="Microsoft",
        subject="Verify your account to avoid suspension",
        body="Your account will be suspended in 24 hours. Verify: http://login.microsoftonline.com.secure-verify.io/auth",
        urls=[{"url": "http://login.microsoftonline.com.secure-verify.io/auth", "anchor": "Verify"}],
        spf_status="FAIL", dmarc_status="FAIL"), 70),
    ("lottery / prize bait", _email(
        sender_address="claims@intl-lottery-winners.org", display_name="International Lottery Commission",
        subject="Congratulations! You have won $1,500,000.00 USD",
        body="To claim your prize, send your full name, address, and bank details within 7 days.",
        spf_status="FAIL", dmarc_status="FAIL"), 70),
    ("sextortion / bitcoin", _email(
        sender_address="you@yourdomain.com",
        subject="I know your password: hunter2",
        body="I have recorded you. Send $1200 in bitcoin to wallet 1A2b3C within 48 hours.",
        spf_status="FAIL", dmarc_status="FAIL"), 70),
    ("unicode homoglyph domain (cyrillic a)", _email(
        sender_address="security@pаypal.com", display_name="PayPal",
        subject="Confirm your identity",
        body="Please confirm your identity: http://pаypal.com/confirm",
        urls=[{"url": "http://pаypal.com/confirm", "anchor": "Confirm"}],
        spf_status="FAIL", dmarc_status="FAIL"), 35),
]

LEGIT = [
    ("real Google security alert", _email(
        sender_address="no-reply@accounts.google.com", display_name="Google",
        subject="Security alert",
        body="A new sign-in on Windows. Review activity: https://myaccount.google.com/notifications",
        urls=[{"url": "https://myaccount.google.com/notifications", "anchor": "Review"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real GitHub notification", _email(
        sender_address="notifications@github.com", display_name="GitHub",
        subject="[org/repo] Pull request #42: Fix login bug",
        body="octocat commented on pull request #42: https://github.com/org/repo/pull/42",
        urls=[{"url": "https://github.com/org/repo/pull/42", "anchor": "View on GitHub"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real Stripe receipt", _email(
        sender_address="receipts@stripe.com", display_name="Stripe",
        subject="Your receipt from Acme Inc [#1234-5678]",
        body="Thanks for your payment. View receipt: https://pay.stripe.com/receipts/abc123",
        urls=[{"url": "https://pay.stripe.com/receipts/abc123", "anchor": "View receipt"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real bank fraud alert with urgency, real domain", _email(
        sender_address="fraud-prevention@wellsfargo.com", display_name="Wells Fargo Fraud Prevention",
        subject="We've temporarily locked your card - immediate action needed",
        body="For your protection we locked your card ending 1234. Call the number on your card "
             "or sign in to confirm: https://www.wellsfargo.com/fraud",
        urls=[{"url": "https://www.wellsfargo.com/fraud", "anchor": "Confirm activity"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real Amazon: verify payment, order on hold", _email(
        sender_address="payments-update@amazon.com", display_name="Amazon.com",
        subject="Your order is on hold - update your payment method",
        body="We couldn't charge your card for order 112-3. Update within 24 hours or it will be cancelled: "
             "https://www.amazon.com/payments",
        urls=[{"url": "https://www.amazon.com/payments", "anchor": "Update payment"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real Bank of America (multi-word brand vs squashed domain)", _email(
        sender_address="alerts@bankofamerica.com", display_name="Bank of America",
        subject="Unusual activity detected on your account",
        body="We detected a $450 charge that doesn't match your usual activity. Sign in: "
             "https://www.bankofamerica.com/activity",
        urls=[{"url": "https://www.bankofamerica.com/activity", "anchor": "Review activity"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real Coinbase: verify identity, urgency, real domain", _email(
        sender_address="no-reply@coinbase.com", display_name="Coinbase",
        subject="Action required: complete verification within 48 hours",
        body="Complete identity verification within 48 hours or your account features will be limited: "
             "https://www.coinbase.com/verify",
        urls=[{"url": "https://www.coinbase.com/verify", "anchor": "Complete verification"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real DocuSign envelope, urgency, real domain", _email(
        sender_address="dse_na3@docusign.net", display_name="DocuSign EU",
        subject="Please DocuSign: Employment Agreement - Signature required today",
        body="Review Document: https://na3.docusign.net/signing/xyz",
        urls=[{"url": "https://na3.docusign.net/signing/xyz", "anchor": "Review Document"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real password reset with /reset/verify path", _email(
        sender_address="security@github.com", display_name="GitHub",
        subject="[GitHub] Please reset your password",
        body="A password reset was requested. Reset it: https://github.com/password_reset/verify/abc123token . "
             "If you didn't request this, ignore this email.",
        urls=[{"url": "https://github.com/password_reset/verify/abc123token", "anchor": "Reset password"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("internal IT: password rotation, action required, real domain", _email(
        sender_address="it-helpdesk@corp.acme.com", display_name="Acme IT Helpdesk",
        subject="Action required: password rotation policy update",
        body="Corporate passwords must be rotated every 90 days starting next month. No action today. "
             "Details: https://intranet.acme.com/security/passwords",
        urls=[{"url": "https://intranet.acme.com/security/passwords", "anchor": "Read policy"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real IRS notice, .gov, tax + refund words", _email(
        sender_address="noreply@irs.gov", display_name="Internal Revenue Service",
        subject="Important information about your tax return",
        body="We need to verify some information before we can process your refund. Sign in: "
             "https://www.irs.gov/account",
        urls=[{"url": "https://www.irs.gov/account", "anchor": "Sign in"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("real Zoom recording ready", _email(
        sender_address="no-reply@zoom.us", display_name="Zoom",
        subject="Cloud Recording - Weekly Standup is now available",
        body="Your cloud recording is ready. View: https://zoom.us/rec/share/abc",
        urls=[{"url": "https://zoom.us/rec/share/abc", "anchor": "View recording"}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
    ("legit invoice with real PDF attachment", _email(
        sender_address="invoicing@quickbooks.com", display_name="QuickBooks",
        subject="Invoice #INV-2024 from Acme Consulting",
        body="Please find attached invoice INV-2024 for $1,200.00 due Sep 15. "
             "View online: https://quickbooks.intuit.com/invoice/2024",
        urls=[{"url": "https://quickbooks.intuit.com/invoice/2024", "anchor": "View invoice"}],
        attachments=[{"filename": "Invoice_INV-2024.pdf", "size": 88000}],
        spf_status="PASS", dkim_status="PASS", dmarc_status="PASS")),
]

MALFORMED = [
    ("empty", _email(sender_address="", subject="")),
    ("sender only", _email(sender_address="someone@example.com", subject="")),
    ("unicode subject", _email(sender_address="test@example.com",
                               subject="Ｈｅｌｌｏ 你好",
                               body="unicode body ✓")),
]


def test_no_false_negatives():
    bad = []
    for name, em, floor in PHISH:
        s = E.investigate(em)["risk_score"]
        if s < floor:
            bad.append(f"{name}: {s} < {floor}")
    assert not bad, "phishing scored too low:\n  " + "\n  ".join(bad)


def test_no_false_positives():
    bad = []
    for name, em in LEGIT:
        s = E.investigate(em)["risk_score"]
        if s >= 35:
            bad.append(f"{name}: {s} >= 35 (indicators: {[i['name'] for i in E.investigate(em)['indicators']]})")
    assert not bad, "legitimate mail flagged:\n  " + "\n  ".join(bad)


def test_malformed_input_does_not_crash():
    for name, em in MALFORMED:
        r = E.investigate(em)
        assert "risk_score" in r and r["risk_score"] < 35, f"{name} -> {r.get('risk_score')}"


def test_clear_phish_scores_high():
    """The unambiguous attacks should land firmly in the phishing band, not just scrape past 70."""
    clear = ["paypal homoglyph + urgency", "display-name spoof, homoglyph domain",
             "deceptive anchor text (HTML phish)"]
    for name, em, _ in PHISH:
        if name in clear:
            s = E.investigate(em)["risk_score"]
            assert s >= 85, f"{name}: {s} < 85"


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
