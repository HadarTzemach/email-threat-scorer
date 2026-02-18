# Email Threat Scorer - Gmail Add-on

## Overview

A Gmail Add-on that analyzes opened emails and produces a maliciousness score (0–100) with an explainable verdict (Safe / Suspicious / Malicious). Built as a home task for the Upwind student program.

## Architecture

The entire solution runs within **Google Apps Script** - no external backend server required. When a user opens an email in Gmail, the add-on automatically triggers, extracts email metadata and content, runs multiple analysis checks, queries VirusTotal for link and file reputation, and displays results in a card UI panel on the right side of Gmail.

```
┌─────────────────────────────────────────────────┐
│                    Gmail UI                       │
│                                                   │
│  ┌─────────────┐    ┌──────────────────────────┐ │
│  │   Email      │    │  Email Threat Scorer     │ │
│  │   Content    │    │  ┌────────────────────┐  │ │
│  │              │    │  │ Score: XX/100       │  │ │
│  │              │    │  │ Verdict: Safe/...   │  │ │
│  │              │    │  │ Findings: ...       │  │ │
│  │              │    │  │ Actions: Blacklist  │  │ │
│  │              │    │  └────────────────────┘  │ │
│  └─────────────┘    └──────────────────────────┘ │
└─────────────────────────────────────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  Google Apps      │
                 │  Script Engine    │
                 │                   │
                 │  • analyzeSender  │
                 │  • analyzeContent │
                 │  • analyzeLinks   │
                 │  • analyzeAttach. │
                 │  • checkBlacklist │
                 │  • checkVirusTotal│
                 └────────┬─────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
     ┌────────────────┐    ┌──────────────────┐
     │  VirusTotal    │    │  User Properties │
     │  API v3        │    │  (Blacklist)     │
     │  • URL check   │    │                  │
     │  • File hash   │    │  Script Props    │
     │                │    │  (API Key)       │
     └────────────────┘    └──────────────────┘
              ▲
              │
     ┌────────────────┐
     │  CacheService  │
     │  (VT results   │
     │   6hr TTL)     │
     └────────────────┘
```

## Implemented Features

### 1. Email Content and Metadata Analysis
- **Sender analysis**: Reply-To mismatch detection, free email provider identification, suspicious domain patterns (excessive length, many numbers)
- **Content analysis**: Urgency/phishing phrase detection using regex word boundaries, sensitive information request detection, excessive CAPS in subject, empty subject detection
- **Link analysis**: IP-based URLs, shortened links, subdomain spoofing (e.g., `paypal.com.evil.ru`), suspicious keywords in URLs

### 2. Attachment Analysis
- **Dangerous file types**: Detection of executable and script extensions (exe, bat, vbs, js, ps1, etc.)
- **Suspicious file types**: Detection of archives and macro-enabled documents (zip, rar, docm, xlsm, etc.)
- **Double extension detection**: Catches social engineering tricks like `invoice.pdf.exe` or `report.docm.pdf` — checks all extensions in the filename, not just the last one
- **Whitespace stripping**: Detects evasion attempts like `invoice.pdf .exe`
- **VirusTotal hash lookup**: Computes SHA-256 hash of attachments and checks against ~70 antivirus engines
- **Large file protection**: Skips VT scan for attachments over 5MB to avoid execution timeouts

### 3. Dynamic Enrichment via External APIs
- **VirusTotal API v3**: Checks URLs and file hashes against ~70 antivirus engines
- **Caching**: Results cached for 6 hours via CacheService to respect rate limits (4 req/min on free tier)
- **Secure key storage**: API key stored in ScriptProperties, never exposed in source code

### 4. Risk Scoring and Verdict
- Score range: 0–100
- Verdicts: **Safe** (0–29), **Suspicious** (30–59), **Malicious** (60–100)
- Each check contributes a weighted score with caps to prevent any single signal from dominating

### 5. Explainability
- Every signal that contributed to the score is displayed with a description
- Users can see exactly why an email received its score

### 6. User-Managed Blacklist
- Blacklist specific sender emails or entire domains via buttons in the UI
- **Blacklist Manager**: Full management interface to view, add, and remove entries
- Subdomain matching: blacklisting `spam.com` also catches `mail.spam.com`
- Manual entry: add emails or domains directly from the management interface
- Stored per-user via PropertiesService

## APIs Used

| API | Purpose | Auth |
|-----|---------|------|
| Gmail API (via GmailApp) | Read email content, headers, metadata, attachments | OAuth (gmail.readonly) |
| VirusTotal API v3 | URL reputation and file hash checking | API Key (free tier, stored in ScriptProperties) |
| Google CardService | Build the add-on UI | Built-in |
| Google PropertiesService | Store user blacklist and API key | Built-in |
| Google CacheService | Cache VirusTotal results (6hr TTL) | Built-in |

## Scoring Weights

| Check | Points | Rationale |
|-------|--------|-----------|
| Reply-To mismatch | +25 | Strong phishing indicator |
| Free email provider | +5 | Weak signal alone, contributes in combination |
| Long domain (>30 chars) | +15 | Common in auto-generated malicious domains |
| Many numbers in domain | +10 | Uncommon in legitimate domains |
| Urgency phrases | +8 per match (max 30) | Scaled with cap to avoid over-penalizing marketing emails |
| Sensitive info request | +20 | Strong social engineering indicator |
| Excessive CAPS in subject | +10 | Common spam tactic |
| Empty subject | +10 | Unusual for legitimate emails |
| IP-based URL | +25 | Legitimate sites don't use IP addresses |
| Shortened links | +15 | Hides real destination |
| Subdomain spoofing | +30 | Direct brand impersonation attempt |
| Suspicious URL keywords | +5 per match (max 20) | Scaled with cap |
| Dangerous attachment type | +30 | Executable/script files are high-risk |
| Double extension | +25 | Classic social engineering trick |
| Suspicious attachment type | +10 | Archives and macro-enabled files carry risk |
| VT: URL flagged (2+ engines) | +15 | Moderate threat signal |
| VT: URL flagged (5+ engines) | +30 | Strong threat signal |
| VT: File hash flagged (2+) | +15 | Moderate threat signal |
| VT: File hash flagged (5+) | +30 | Strong threat signal |
| Blacklisted sender/domain | +50 | User explicitly flagged |

## Security Considerations

- **API Key Protection**: VirusTotal API key stored in ScriptProperties, never hardcoded in source
- **Rate Limit Management**: CacheService caches VT results for 6 hours; URL checks limited to 5 per email
- **Safe Attachment Handling**: Files are never executed — only hashed (SHA-256) and checked against VT database
- **Large File Protection**: Attachments over 5MB are skipped to prevent execution timeouts
- **Whitespace Evasion Detection**: Filenames are stripped of whitespace before analysis to catch tricks like `file.pdf .exe`
- **Privacy Note**: VirusTotal retains metadata about hash queries. For sensitive organizations, a private VT instance or internal sandbox would be recommended.

## Limitations and Trade-offs

### Not Implemented
- **History of Actions**: Would track previous scans per user. Would use PropertiesService or Google Sheets as a lightweight database.
- **Management Console**: Full settings UI for adjusting scoring thresholds, managing whitelists, configuring sensitivity levels. Partially implemented via Blacklist Manager.
- **SPF/DKIM/DMARC Validation**: Would significantly reduce false positives on legitimate senders (e.g., Google, banks) but requires parsing raw email headers.
- **HTML Link Mismatch Detection**: Detecting when displayed URL text differs from actual href. Requires parsing HTML body via `getRawContent()`.
- **Punycode/IDN Attack Detection**: Internationalized domain name attacks using `xn--` prefixed domains.

### Known False Positive Scenarios
- Legitimate security alerts (from Google, banks) contain urgency phrases and suspicious URL keywords, resulting in scores of 20–30 even though they are safe
- Marketing emails with shortened tracking links get flagged

### Design Decisions
- **All-in-one Apps Script**: No external backend to simplify deployment and reduce attack surface. Trade-off: limited compute power and 6-minute execution timeout.
- **Weighted scoring with caps**: Prevents any single category from pushing the score to Malicious alone, except for genuinely dangerous combinations (e.g., dangerous attachment + VT flagged).
- **Conservative VirusTotal thresholds**: Single-engine detections are ignored to avoid false positives from overly aggressive engines.
- **Word boundary regex**: Prevents false positives from partial word matches (e.g., "password" inside "compassion").
- **No attachment cap**: A file like `invoice.pdf.exe` flagged by VT deserves a high score — intentionally no cap on attachment scoring.

## Setup Instructions

1. Go to [script.google.com](https://script.google.com) and create a new project
2. Copy the code into `Code.gs`
3. Update `appsscript.json` with the provided manifest
4. Set your VirusTotal API key securely:
   - In `setApiKey()`, replace `"YOUR_API_KEY_HERE"` with your key (free at [virustotal.com](https://www.virustotal.com))
   - Select `setApiKey` from the function dropdown and click Run
   - Change the key back to `"YOUR_API_KEY_HERE"` and save (so the key isn't in source code)
5. Deploy → Test deployments → Install
6. Open any email in Gmail — the add-on appears in the right panel

## Tech Stack

- Google Apps Script (V8 runtime)
- Google Workspace Gmail Add-on API
- VirusTotal API v3
- CardService UI framework
- CacheService for rate limit management
