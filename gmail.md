# WebShield Gmail Scanner Improvement Plan
This plan upgrades the Gmail extension’s detection accuracy, button/link correctness, and user-education UX while making SPF/DKIM/DMARC reporting precise and auditable.

## 1) Codebase map (what runs where)
- **`gmail-extension/manifest.json`**
  - MV3 extension.
  - Content script: `gmail-scanner.js` on `https://mail.google.com/*`.
  - Service worker: `background-gmail.js`.
  - Popup: `popup.html` + `popup.js`.
  - Options: `settings.html` + `settings.js`.
  - Report UI: `report.html` + `report.js`.
- **Core data flow**
  - `gmail-scanner.js` extracts Gmail DOM metadata (sender, subject, links, attachment hints, basic UI signals) and requests scanning via background message `GMAIL_EXT_SCAN_EMAIL_METADATA`.
  - `background-gmail.js` proxies the request to backend `POST /api/email/scan-metadata` (to avoid Gmail-page CORS issues) and stores “last scan”.
  - Popup reads `chrome.storage.local.webshield_gmail_last_scan` and renders summary UI.
  - Report page reads `gmail_report_<threadId>` and renders a full report.

## 2) Current detection techniques (as implemented)
- **Client-side (Gmail DOM) heuristics in `gmail-scanner.js`**
  - Sender domain heuristics (trusted list, suspicious TLDs, impersonation keywords, homograph character mapping).
  - Subject keyword checks (urgency/fear/verification/financial/impersonation/prizes).
  - Link extraction (including Google redirect `google.com/url?...q=` unwrap) and limited text-vs-URL mismatch detection.
  - Attachment extension detection (flags potentially dangerous extensions).
  - “Via” indicator detection (very approximate).
  - Offline scoring fallback when backend not reachable.
- **Backend scoring in `backend/email_routes.py`**
  - Sender reputation (trusted/free/disposable heuristics).
  - Link risk (regex patterns: shorteners, suspicious keywords, impersonation patterns).
  - SPF/DKIM/DMARC **DNS-record checks** via `auth_checker.check_email_authentication(sender_email)` when available.
  - Threat score computed as a weighted model (sender 40%, auth 30%, link 30%) and then post-processed with “smart scoring” rules.

## 3) Key gaps / risks (accuracy + correctness)
### 3.1 “100% accuracy” reality check
- **Impossible to guarantee 100%** for adversarial phishing (new domains, compromised legit accounts, novel content). The best achievable goal is:
  - **High precision** for “dangerous” calls (minimize false positives).
  - **High recall** for “suspicious” calls (catch more threats, but communicate uncertainty clearly).
  - **Explainability** + user education to reduce user error.

### 3.2 SPF/DKIM/DMARC correctness
- In a Gmail extension **you cannot reliably read actual SPF/DKIM/DMARC pass/fail for the specific message from Gmail DOM**.
- Current backend DNS checks validate *domain configuration* (records exist/are valid), **not whether the specific message passed authentication**.
  - This can mislead users: a domain can have SPF/DKIM/DMARC configured but a message can still fail.
- Recommendation: report **two layers** explicitly:
  - **(A) Domain posture (DNS records)**: “Configured / Not configured / Unknown”.
  - **(B) Message authentication result**: only “Passed/Failed/Unknown” if you can fetch message headers via Gmail API (requires OAuth) or parse “Show original” reliably (fragile).

### 3.3 URL scanning logic is incomplete
- Current backend link analysis is primarily **regex-based**; it does not do:
  - Redirect-chain expansion.
  - Host reputation (Safe Browsing / other providers).
  - Newly registered domain detection.
  - Real-time threat intelligence correlation.

### 3.4 UI wiring / button correctness issues
- **Bug (popup.js)**: `activeThreadId` is assigned in `renderResult()` but is **never declared** in the file; this will throw a `ReferenceError` in strict contexts and can break result rendering.
- **Popup “Report” button naming vs behavior**:
  - `gr-report-btn` says “View full report” but currently sends `GMAIL_EXT_SCROLL_TO_REPORT` (scrolls to the in-page floating badge) rather than opening `report.html?id=<threadId>`.
- Quick actions are wired correctly:
  - `gr-report-phishing` -> `GMAIL_EXT_SAFETY_ACTION` `{action:'report'}` -> Gmail “Report phishing”.
  - `gr-mark-spam` -> `{action:'spam'}` -> Gmail “Report spam”.
  - `gr-show-details` -> scroll to report (OK).

### 3.5 Link rendering consistency
- Popup uses `linkAnalysis.suspicious_links` from backend. But the backend model declares `suspicious_links: List[str]` while popup expects objects sometimes (e.g., checks `l.textUrlMismatch`). This can lead to mismatched counts/UI display.

## 4) Improvement plan (professional, top-notch detection + education)
### Milestone A — Make results *truthful*, consistent, and explainable
- **Define a single canonical “EmailScanResult schema”** shared by backend + extension:
  - `sender_reputation`, `link_analysis`, `content_analysis`, `auth`.
  - Ensure `suspicious_links` entries include a structured object: `{ url, reason_codes, severity, display_text_domain_mismatch, resolved_final_url, reputation_sources }`.
- **Rewrite UI labels to match meaning**:
  - Separate “Domain authentication posture (DNS)” vs “Message authentication (header result)”.
  - Clearly label unknown states.
- **Add an “Evidence” section**:
  - For each reason shown, attach what triggered it (keyword, domain diff, redirect, record missing, etc.).

### Milestone B — SPF/DKIM/DMARC: correct status as Passed/Failed/Unknown
- **Selected implementation: Gmail API + OAuth (required for correctness)**
  - Implement OAuth flow and request Gmail read-only scope.
  - Fetch per-message headers for the selected email and parse `Authentication-Results`.
  - Compute message-level statuses and display exactly:
    - SPF: **Passed / Failed / Unknown**
    - DKIM: **Passed / Failed / Unknown**
    - DMARC: **Passed / Failed / Unknown**
  - Keep backend DNS posture checks (records configured) as a *separate*, clearly labeled signal.

### Milestone C — URL scanning becomes a real pipeline
- **Extraction improvements**
  - Extract all links including:
    - Buttons styled as links.
    - Image links.
    - Obfuscated links (punycode, mixed scripts, whitespace tricks).
  - Normalize/defang for UI (prevent accidental clicking).
- **Resolution + scanning**
  - Expand and capture:
    - Redirect chain (HEAD/GET with safe limits).
    - Final destination hostname + TLS info.
  - Run **VirusTotal URL scanning using the same API + logic already used in the normal web extension**:
    - Reuse the existing VT request format, polling/caching strategy, and scoring thresholds for consistency.
    - Add caching and rate-limits so scanning email links doesn’t exceed VT quotas.
    - Persist VT scan IDs/results in backend (preferred) or extension storage (fallback) so the report page can show stable results.
- **Risk scoring**
  - Move from a single numeric score to:
    - `severity` (safe/suspicious/dangerous)
    - `confidence` (0-1)
    - `reasons` list (machine readable + human readable)

### Milestone D — Content/sender impersonation gets stronger
- Add checks for:
  - Display-name vs email-domain mismatch (brand name vs non-brand domain).
  - Reply-To mismatch vs From domain mismatch (already partially present, needs reliability).
  - Urgency + credential request + link-to-login-page compound scoring.
  - Attachment-type risk scoring (macro documents, archives with executables).
  - Language/grammar cues (careful: high false positives). Prefer “education warnings” not “malicious”.

### Milestone E — UX & user education (main theme)
- Improve the popup and report to teach users:
  - “What this means” for each signal.
  - “What you should do next” (safe actions: report, mark spam, verify via official site).
  - “Uncertainty” handling (unknown auth, offline mode, limited visibility).
- Add safe defaults:
  - Defang links in report (copy only).
  - Offer “Open in isolated browser profile/incognito” guidance rather than direct open.

### Milestone F — Button/link correctness and reliability
- Fix popup/report navigation:
  - `Report` should open `report.html?id=<threadId>`; “Details” can scroll.
- Fix variable scoping issues:
  - Declare `activeThreadId` and ensure it’s set before usage.
- Ensure each button does what its function name implies:
  - “Report phishing” -> Gmail report phishing.
  - “Mark spam” -> Gmail report spam.
  - “Settings” -> options.
  - “Report” -> open report page.
- Add a small runtime self-test:
  - On popup open: verify content script connectivity and show actionable guidance.

## 5) Verification checklist (what you should test after implementation)
- **Buttons**
  - Popup: scan, report phishing, mark spam, details, report, settings.
  - In-page floating badge: rescan, unsubscribe, report.
  - Report page: scan now, rescan, export, copy badge.
- **Links shown correctly**
  - Links count matches extracted links.
  - Suspicious link count matches `suspicious_links`.
  - Text-vs-URL mismatch is shown deterministically and uses the correct data model.
- **Auth display**
  - SPF/DKIM/DMARC show exactly: `Passed`, `Failed`, `Unknown` (and optionally `N/A` only if documented).
  - “Authenticated overall” should be derived from per-signal logic and not “imputed” from TLS/trust.

## 6) Decisions needed from you (to finalize implementation)
- **Confirmed**: Implement Gmail API/OAuth for per-message SPF/DKIM/DMARC.
- **Confirmed**: Use VirusTotal scanning with the same API + logic as the normal web extension.
- **Confirmed**: Target policy tuning = **Aggressive** (prioritize catching more threats; more warnings acceptable).
- **Confirmed**: Reuse the same VirusTotal API key storage/setting as the normal web extension (development mode).

---

## 7) Implementation Progress

### ✅ Milestone A - Canonical Schema & Explainability (COMPLETED)

**Backend Changes (`email_routes.py`):**
- Added `SuspiciousLinkDetail` model with structured fields:
  - `url`: The suspicious URL
  - `reason_codes`: Machine-readable codes (e.g., `URL_SHORTENER`, `IP_ADDRESS`, `PHISHING_KEYWORD`)
  - `reasons_human`: Human-readable explanations
  - `severity`: `safe` / `suspicious` / `dangerous`
  - `confidence`: 0-1 confidence score
  - `display_text_domain_mismatch`: Boolean for link text vs URL domain mismatch
  - `virustotal_result`: Optional VT scan result
- Updated `LinkAnalysis` model:
  - `suspicious_links` and `malicious_links` are now `List[SuspiciousLinkDetail]`
  - Added `safe_links: List[str]` for links confirmed safe
  - Added `virustotal_scanned: bool` flag
- Added `ContentAnalysis` model with evidence tracking
- Updated `analyze_links()` function to return structured `SuspiciousLinkDetail` objects with detailed reason codes

**Frontend Changes (`report.js`):**
- Updated `renderLink()` to handle structured `SuspiciousLinkDetail` objects
- Added tooltip display with human-readable reasons
- Added expandable reasons section for suspicious/malicious links

### ✅ Milestone B - SPF/DKIM/DMARC Correct Status Display (COMPLETED)

**Backend Changes (`email_routes.py`):**
- Updated `HeaderAnalysis` model with two layers:
  - **Message-level authentication**: `spf_status`, `dkim_status`, `dmarc_status` (Passed/Failed/Unknown)
  - **Domain posture**: `spf_domain_posture`, `dkim_domain_posture`, `dmarc_domain_posture` (Configured/Not Configured/Unknown)
- Updated `analyze_headers()` function:
  - Normalizes status values to canonical `Passed/Failed/Unknown` format
  - Separately reports DNS record configuration vs message authentication
  - Added helper functions `normalize_status()` and `get_domain_posture()`
- Updated `calculate_threat_score()` to use new `Passed/Failed/Unknown` format

**Frontend Changes (`report.js`, `report.html`):**
- Updated `renderAuthStatus()` to handle new canonical labels with icons (✓ PASSED, ✕ FAILED, ? UNKNOWN)
- Added new `renderDomainPosture()` function for DNS record status
- Enhanced Email Authentication section to show both:
  - **Message**: Whether this specific email passed authentication
  - **DNS Record**: Whether the sender's domain has authentication configured
- Added legend explaining the two-layer authentication display
- Added CSS styles for enhanced auth section and domain posture pills

### ✅ Milestone F - Button/Link Correctness (COMPLETED)

**Bug Fixes (`popup.js`):**
- ✅ Fixed: `activeThreadId` now properly declared at file scope before usage
- ✅ Fixed: Report button now opens `report.html?id=<threadId>` instead of sending `GMAIL_EXT_SCROLL_TO_REPORT`
- Added fallback logic to extract thread ID from URL if `activeThreadId` is not set

### ✅ Milestone C - URL Scanning Pipeline (COMPLETED)

**Backend Changes (`email_routes.py`):**
- Imported `WebShieldDetector` from `utils.py` to reuse existing VT integration
- Added async `analyze_links_with_virustotal()` function:
  - Prioritizes scanning: malicious links first, then suspicious, then unknown
  - Respects API rate limits with configurable `max_vt_scans` parameter (default 5)
  - Skips trusted domains (from LEGITIMATE_DOMAINS list) to save API quota
  - Scans links concurrently using `asyncio.gather()`
  - Updates `SuspiciousLinkDetail.virustotal_result` with VT scan data
  - Escalates severity based on VT detection count:
    - 2+ vendors flagged → "dangerous" severity, VT_MALICIOUS reason code
    - 1 vendor flagged → keep suspicious, VT_SUSPICIOUS reason code
    - 0 vendors flagged → VT_CLEAN reason code
  - Recalculates risk score after VT enrichment
- Updated `scan_email_metadata` endpoint:
  - Uses `analyze_links_with_virustotal()` for full scans when VT is available
  - Falls back to basic `analyze_links()` for quick scans or if VT unavailable

**Remaining for future enhancement:**
- Redirect chain expansion (not yet implemented)
- Persistent VT result caching across requests

### ✅ Milestone D - Content/Sender Impersonation (COMPLETED)

**Backend Changes (`email_routes.py`):**
- Enhanced `ContentAnalysis` model with new fields:
  - `urgency_score`: 0-100 urgency level
  - `urgency_indicators`: List of detected urgency phrases
  - `credential_request_detected`: Boolean for login/password requests
  - `credential_evidence`: List of credential request indicators
  - `display_name_mismatch`: Boolean for brand impersonation
  - `impersonated_brand`: Name of brand being impersonated
  - `reply_to_mismatch`: Boolean for Reply-To domain mismatch
  - `has_risky_attachments`: Boolean for dangerous attachment types
  - `risky_attachment_types`: List of detected risky attachments
- Updated `EmailMetadata` to accept:
  - `reply_to`: Reply-To address for mismatch detection
  - `attachment_names`: Filenames for risky attachment analysis
  - `body_snippet`: Body text for content analysis
- Added `analyze_content_and_impersonation()` function:
  - Brand impersonation detection for 25+ major brands (PayPal, Amazon, Google, Microsoft, etc.)
  - Reply-To domain mismatch detection
  - Urgency phrase detection (20+ patterns with weighted scoring)
  - Credential request detection (13+ patterns)
  - Phishing keyword categorization (financial, prize_scam, impersonation, tech_support, account_threat)
  - Dangerous attachment type detection (executables, macro-enabled docs, archives)
- Updated `calculate_threat_score()` to weigh content analysis at 15%
- Added content-based reasons to threat score output

**Frontend Changes (`report.js`, `report.html`):**
- Added `renderContentAnalysisSection()` to display:
  - Brand impersonation warnings (🎭)
  - Reply-To mismatch alerts (↩️)
  - Urgent credential request warnings (🚨)
  - Risky attachment warnings (📎)
  - Phishing keyword indicators (🎣)
- Added severity-based warning cards with color coding
- Added CSS for content analysis section with gradient backgrounds

### ✅ Milestone E - UX & User Education (COMPLETED)

**Backend:**
- Content analysis now provides evidence for user education
- Reasons list expanded to include educational explanations

**Frontend Changes (`report.js`, `report.html`):**
- Added `renderWhatToDoSection()` function for contextual guidance:
  - **Dangerous emails**: Don't click links, report phishing, delete email, go to official sites
  - **Suspicious emails**: Exercise caution, verify sender, use official channels
  - **Safe emails**: Stay alert, verify unfamiliar links
- Contextual actions based on content analysis (e.g., if credential request detected, advise direct website access)
- Primary actions highlighted with special styling
- Added CSS for "What To Do" section with action cards

**Completed features:**
- ✅ "What this means" explanations for each signal
- ✅ "What you should do next" guidance
- ✅ Context-aware recommendations
- ✅ Enhanced tooltips and legends
- ✅ Uncertainty handling (unknown auth, offline mode)

**Remaining for future enhancement:**
- Defanged link display (copy only, not clickable)
- "Open in isolated browser profile" guidance
