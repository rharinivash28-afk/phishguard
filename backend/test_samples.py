SAMPLE_EMAILS = [
    {
        "id": "sample_ps02_paypal",
        "title": "PS-02 Problem Statement: PayPal Account Suspension",
        "sender_address": "security@paypa1-login.com",
        "display_name": "PayPal Security Team",
        "subject": "Your account will be suspended within 24 hours!",
        "recipient": "harinivash28082007@gmail.com",
        "date": "2026-09-01 09:42 AM",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "body": "Dear Harinivash,\n\nWe detected suspicious unauthorized login attempts on your account from an unknown device in Moscow, Russia.\n\nYour account will be suspended within 24 hours unless you verify your identity and confirm your credentials immediately.\n\nPlease follow the link below to restore access:\nhttp://paypa1-login.com/verify\n\nFailure to comply will result in permanent account termination.\n\nPayPal Security Operations",
        "urls": [
            {
                "url": "http://paypa1-login.com/verify",
                "anchor": "http://paypa1-login.com/verify"
            }
        ],
        "attachments": []
    },
    {
        "id": "sample_m365_spoof",
        "title": "Microsoft 365 Password Expiry Spearphish",
        "sender_address": "admin-alert@m1crosoft-auth.net",
        "display_name": "Microsoft 365 Cloud Admin",
        "subject": "Critical: Your Office 365 Password expires in 2 hours",
        "recipient": "harinivash28082007@gmail.com",
        "date": "2026-09-01 08:15 AM",
        "spf_status": "FAIL",
        "dkim_status": "NONE",
        "dmarc_status": "FAIL",
        "body": "Your corporate Microsoft Office 365 password is set to expire today. To keep your current password and avoid disruption to Outlook and Teams, verify your password now.\n\nKeep Same Password: https://office365.com/login\n\nIT Support Desk",
        "urls": [
            {
                "url": "http://185.220.101.5/m365-login/auth.php",
                "anchor": "https://office365.com/login"
            }
        ],
        "attachments": []
    },
    {
        "id": "sample_netflix_billing",
        "title": "Netflix Fake Billing Failure Scam",
        "sender_address": "billing-support@netfl1x-billing.co",
        "display_name": "Netflix Billing Service",
        "subject": "Urgent: We were unable to process your monthly subscription payment",
        "recipient": "harinivash28082007@gmail.com",
        "date": "2026-09-01 07:30 AM",
        "spf_status": "SOFTFAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "body": "Hi Harinivash,\n\nWe had trouble with your billing info for the next cycle. Your membership has been put on hold.\n\nPlease update your billing details immediately within 12 hours so you can continue streaming without interruption.\n\nUpdate Details: http://netfl1x-billing.co/account-update\n\n- The Netflix Team",
        "urls": [
            {
                "url": "http://netfl1x-billing.co/account-update",
                "anchor": "Update Details"
            }
        ],
        "attachments": []
    },
    {
        "id": "sample_docusign_macro",
        "title": "DocuSign Weaponized Macro Payload",
        "sender_address": "documents@docus1gn-sign.com",
        "display_name": "DocuSign Signature Service",
        "subject": "Action Required: Sign Employment Contract Agreement (Urgent)",
        "recipient": "harinivash28082007@gmail.com",
        "date": "2026-09-01 06:10 AM",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "body": "Please review and sign the attached legal contract immediately.\n\nAll signatures must be completed before end of business today. Open the attached document and enable macros to review signed copy.",
        "urls": [
            {
                "url": "http://docus1gn-sign.com/d/938210",
                "anchor": "View Completed Document"
            }
        ],
        "attachments": [
            {
                "filename": "Contract_Agreement_2026.pdf.exe",
                "size": 145020
            }
        ]
    },
    {
        "id": "sample_legit_google",
        "title": "Legitimate: Google Security Alert (Benign)",
        "sender_address": "no-reply@accounts.google.com",
        "display_name": "Google",
        "subject": "Security alert: New device signed in to your Google Account",
        "recipient": "harinivash28082007@gmail.com",
        "date": "2026-09-01 09:00 AM",
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "body": "Your Google Account harinivash28082007@gmail.com was just signed in to from a new Windows device.\n\nIf this was you, you don't need to do anything. If not, we will help you secure your account.\n\nCheck activity: https://myaccount.google.com/notifications\n\nYou received this email to let you know about important changes to your Google Account and services.",
        "urls": [
            {
                "url": "https://myaccount.google.com/notifications",
                "anchor": "https://myaccount.google.com/notifications"
            }
        ],
        "attachments": []
    },
    {
        "id": "sample_legit_work",
        "title": "Legitimate: Engineering Sprint Planning (Benign)",
        "sender_address": "alex.chen@techcorp.io",
        "display_name": "Alex Chen",
        "subject": "Agenda for Q3 Sprint 4 Planning & Architecture Sync",
        "recipient": "harinivash28082007@gmail.com",
        "date": "2026-09-01 08:45 AM",
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "body": "Hi Harinivash,\n\nPlease find the sprint board link for our planning call today at 2 PM PST.\n\nBoard link: https://jira.techcorp.io/boards/SPRINT-4\n\nLet me know if you have any questions before the meeting!\n\nBest,\nAlex",
        "urls": [
            {
                "url": "https://jira.techcorp.io/boards/SPRINT-4",
                "anchor": "https://jira.techcorp.io/boards/SPRINT-4"
            }
        ],
        "attachments": []
    }
]
