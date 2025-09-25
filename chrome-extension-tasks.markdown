# QuMail Chrome Extension: Universal Gmail Quantum Security

**Project Overview**: Transform QuMail from an Electron desktop app to a universal Chrome extension for Gmail, enabling quantum-secure email encryption/decryption for any user with the extension installed. Integrates existing hybrid encryption framework (QKD + ML-KEM + ECDH) with Chrome extension APIs, Firebase persistence, and Render hosting. Built for ISRO Smart India Hackathon 2025 demo (Problem Statement ID 25179) with a 2-3 minute presentation showcasing universal Gmail quantum security.

**Objective**: Create a production-ready Chrome extension in ~12-15 hours (1-2 member sub-team, starting 9/26/2025, 02:38 AM IST) that allows Gmail users to encrypt/decrypt emails (including old messages) when the extension is running, without OAuth2 authentication, using Render-hosted Flask backend and Firebase for persistent key storage.

**Architecture**: Chrome Extension → Render-hosted Flask API → Firebase Realtime Database → Gmail DOM/Gmail API

**ISRO Problem Statement Alignment**:
- **Interfaces**: Flask backend (ETSI GS QKD 014 APIs, `/api/qkd/key`, Render-hosted), Gmail web interface (DOM injection, optional Gmail API), violet/purple glassmorphism UI in compose/inbox.
- **Use Case**: Users install extension, toggle QuMail, encrypt/decrypt emails in Gmail with persistent keys. Both sender and receiver need the extension.
- **Security Levels**: Level 1 (QKD OTP), Level 2 (Hybrid AES), Level 3 (ML-KEM + EdDSA/ML-DSA), Level 4 (Plaintext).
- **Modularity**: Supports future Google Workspace apps (chat/video stubs).
- **Challenges**: Seamless Gmail integration, persistent keys, no OAuth2, demo-ready visuals.
- **Preferred Browser**: Chrome/Chromium (Windows/Mac/Linux).

**Tech Stack**:
- **Extension**: Manifest V3, content scripts, background service worker, popup UI.
- **Frontend**: Vanilla JavaScript, Tailwind CSS (violet/purple glassmorphism), Three.js (animations).
- **Backend**: Flask (`/backend/app.py`, ETSI QKD 014, mTLS), Qiskit (BB84 QKD), cryptography.py (ECDH/X25519, EdDSA, AES-256-GCM, HKDF-SHA256), liboqs-python (ML-KEM-768, ML-DSA-6x5), hosted on Render free tier.
- **Storage**: Firebase Realtime Database (keys in `/keys/users/{email}/{keyId}`), chrome.storage.local (toggle state).
- **Email**: Gmail web interface (DOM injection, optional Gmail API), MIME for encrypted content/attachments.
- **Utils**: Chrome APIs (tabs, storage, scripting, webRequest), Firebase Web SDK, Gmail API (optional).
- **Testing**: Chrome DevTools, Playwright.
- **Hardware**: Any Chrome-compatible device (Intel i5/i7, 8-16GB RAM, integrated graphics).

**Key Advantages Over Desktop App**:
- **Universal Access**: Any Gmail user with the extension can encrypt/decrypt.
- **No Login**: No OAuth2 or App Passwords; uses email addresses from Gmail DOM.
- **Persistent Keys**: Firebase ensures decryption of old messages.
- **Global Scale**: Render supports worldwide access.
- **Quantum Security**: 192-bit hybrid encryption for Levels 1-3.

**Current System Status**:
- **Completed**: Electron GUI (glassmorphism, Three.js), Flask backend (QKD, ECDH, ML-KEM, hybrid key), encryption (Levels 1-4), Gmail/Yahoo integration (SMTP/IMAP).
- **Working**: Gmail sending, 4-level encryption/decryption, memory-based storage (`_qkd_key_storage`, `_hybrid_key_storage`).
- **Limitations**: Keys lost on restart, App Passwords insecure for extensions, partial Firebase setup (lines 147-151, `app.py`).

**Task List**: Check off tasks in Cursor IDE. Each task includes a Cursor prompt, action, and contribution. Target ~12-15 hours with 1-2 members. Feed into Cursor: “Understand this QuMail Chrome extension task list and assist with each task, removing OAuth2, using email-based key indexing, ensuring both sender/receiver can encrypt/decrypt with the extension.” Backend hosted on Render (`https://qumail-backend.onrender.com`) with Firebase as primary storage.

## Step 1: Backend Migration and Render Deployment (~2-3 hours, 1 member)
- [ ] **Task 1.1: Update Flask for Render Production**  
  *Description*: Configure Flask app for Render with CORS and Firebase as primary storage.  
  *Prompt*: “Modify QuMail Flask app for Render with CORS for Chrome extension, Firebase as primary key storage, and production settings, without OAuth2.”  
  *Action*: Update `/backend/app.py` with `app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))`, add `flask-cors`. Create `requirements.txt` (`pip freeze > requirements.txt`: Flask, Qiskit, cryptography, liboqs-python, firebase_admin, flask-cors, gunicorn). Set build command: `pip install -r requirements.txt`, start command: `gunicorn app:app`. Remove memory-based storage (`_qkd_key_storage`, `_hybrid_key_storage`) in `encryption.py`.  
  *Contribution*: Enables global backend access.

- [ ] **Task 1.2: Migrate to Firebase Primary Storage**  
  *Description*: Replace memory-based key storage with Firebase using email-based indexing.  
  *Prompt*: “Update QuMail Flask backend to use Firebase Realtime Database as primary storage for QKD, ECDH, ML-KEM, hybrid keys, indexed by email addresses without OAuth2.”  
  *Action*: Update `/backend/app.py` (lines 147-151) and `/backend/encryption.py` to store/retrieve keys in `/keys/users/{email}/{keyId}` with metadata (`sender`, `recipient`, `level`, `key_data`). Set Firebase rules: `{"rules": {"keys": {".read": "data.child('recipient').val() === $email || data.child('sender').val() === $email", ".write": "true"}}}`. Remove memory cache.  
  *Contribution*: Solves key persistence issue.

- [ ] **Task 1.3: Deploy to Render**  
  *Description*: Deploy Flask to Render free tier.  
  *Prompt*: “Deploy QuMail Flask backend to Render with Firebase credentials as environment variables.”  
  *Action*: Create Render account at render.com, connect Git repo, create Web Service (free tier, Python 3.12), set env vars (`FIREBASE_CREDENTIALS=$(cat service-account-key.json)`), use build command: `pip install -r requirements.txt`, start command: `gunicorn app:app`. Test `/api/qkd/key` with curl at `https://qumail-backend.onrender.com`.  
  *Contribution*: Makes backend globally accessible.

- [ ] **Task 1.4: Update API for Chrome Extension**  
  *Description*: Add extension-specific endpoints with email-based key access.  
  *Prompt*: “Add Flask endpoints for QuMail extension: /api/chrome/encrypt, /api/chrome/decrypt, using email addresses for key access without OAuth2.”  
  *Action*: Update `/backend/app.py` with endpoints: `/api/chrome/encrypt` (input: `{plaintext, security_level, sender_email, recipient_email}`, output: `{encrypted_data, metadata: {key_id, level}}`), `/api/chrome/decrypt` (input: `{encrypted_data, key_id, user_email}`, output: `{plaintext}`), generate random UUID `key_id`. Test with Postman.  
  *Contribution*: Provides extension-specific API.

- [ ] **Task 1.5: Add Render Keep-Alive**  
  *Description*: Prevent Render instance sleep for demo.  
  *Prompt*: “Generate script to prevent Render free tier instance sleep for QuMail backend during hackathon demo.”  
  *Action*: Set up free UptimeRobot cron job to ping `https://qumail-backend.onrender.com` every 10 minutes (Render sleeps after 15 minutes).  
  *Contribution*: Ensures demo reliability.

## Step 2: Chrome Extension Foundation (~2-3 hours, 1 member)
- [ ] **Task 2.1: Create Manifest V3**  
  *Description*: Configure manifest with Gmail and Render permissions.  
  *Prompt*: “Generate Manifest V3 for QuMail extension with permissions for Gmail, Render, Firebase, and content scripts, without OAuth2.”  
  *Action*: Create `/chrome-extension/manifest.json`: `"permissions": ["tabs", "storage", "scripting", "webRequest", "https://mail.google.com/*", "https://qumail-backend.onrender.com/*"], "content_scripts": [{ "matches": ["*://mail.google.com/*"], "js": ["content-scripts/gmail-injector.js"] }]`. Add icon paths (16x16, 48x48, 128x128).  
  *Contribution*: Establishes extension framework.

- [ ] **Task 2.2: Create Background Service Worker**  
  *Description*: Handle API and key management without OAuth2.  
  *Prompt*: “Generate Chrome extension background service worker for QuMail to communicate with Render and Firebase, using email-based key access.”  
  *Action*: Create `/chrome-extension/background.js` with `fetch` for Render APIs (`https://qumail-backend.onrender.com/api/chrome/encrypt`, `/decrypt`), Firebase Web SDK. Extract user email from Gmail DOM (`document.querySelector('[data-email]')`).  
  *Contribution*: Manages backend communication.

- [ ] **Task 2.3: Create Popup Interface**  
  *Description*: Build popup with glassmorphism UI.  
  *Prompt*: “Generate QuMail extension popup with violet/purple glassmorphism for toggle and level preferences.”  
  *Action*: Create `/chrome-extension/popup.html`, `/popup.css`, `/popup.js` with Tailwind CDN, toggle switch, and default level settings. Show Firebase connection status.  
  *Contribution*: Provides user controls.

- [ ] **Task 2.4: Implement Toggle Logic**  
  *Description*: Enable/disable UI injection.  
  *Prompt*: “Generate background.js and popup.js to toggle QuMail UI injection using chrome.storage.local.”  
  *Action*: Store toggle state in `chrome.storage.local`, skip content script injection when disabled. Notify `gmail-injector.js` of state changes.  
  *Contribution*: Meets on-demand requirement.

- [ ] **Task 2.5: Test Extension Loading**  
  *Description*: Verify extension loads and connects to Render.  
  *Prompt*: “Generate test script to verify QuMail extension loads and connects to Render without OAuth2.”  
  *Action*: Load in `chrome://extensions/`, test popup and API connectivity (`/api/qkd/key`) in Chrome DevTools.  
  *Contribution*: Validates foundation.

## Step 3: Gmail Interface Integration (~3-4 hours, 1-2 members)
- [ ] **Task 3.1: Create Gmail Content Script**  
  *Description*: Inject QuMail UI into Gmail compose/inbox.  
  *Prompt*: “Generate content script to inject QuMail encryption buttons and dropdown into Gmail compose with violet/purple glassmorphism.”  
  *Action*: Create `/chrome-extension/content-scripts/gmail-injector.js` to detect compose area (`[data-action="compose"]`), inject UI (Tailwind purple-600, violet-500, blur). Check toggle state. Extract user email from DOM.  
  *Contribution*: Integrates QuMail with Gmail.

- [ ] **Task 3.2: Add Encryption Level Selector**  
  *Description*: Inject dropdown for 4 security levels.  
  *Prompt*: “Inject glassmorphism dropdown into Gmail compose for QuMail levels: OTP, AES, PQC, Plaintext.”  
  *Action*: Inject HTML/CSS with Tailwind near Gmail toolbar.  
  *Contribution*: Enables level selection.

- [ ] **Task 3.3: Add Send Secure Button**  
  *Description*: Enhance Gmail’s send button.  
  *Prompt*: “Add QuMail ‘Send Secure’ button to Gmail compose to trigger encryption via Render API.”  
  *Action*: Inject button next to Gmail send, intercept send events, call `/api/chrome/encrypt` with sender/recipient emails, format MIME email.  
  *Contribution*: Enables secure sending.

- [ ] **Task 3.4: Add Decrypt Interface**  
  *Description*: Auto-detect and decrypt emails in inbox.  
  *Prompt*: “Generate content script to auto-detect QuMail-encrypted emails in Gmail inbox and add decrypt button with violet/purple badge.”  
  *Action*: Scan for `[QuMail Encrypted]` and `X-QuMail-KeyID`, inject “Decrypt” button, call `/api/chrome/decrypt` with `key_id` and user email.  
  *Contribution*: Enables decryption UI.

- [ ] **Task 3.5: Handle Gmail UI Changes**  
  *Description*: Ensure robust UI injection.  
  *Prompt*: “Create robust Gmail UI detection for QuMail extension using MutationObservers to handle interface changes.”  
  *Action*: Use flexible selectors (e.g., `[data-action="compose"]`), add MutationObserver for compose/inbox changes, test with Gmail variations.  
  *Contribution*: Maintains compatibility.

## Step 4: Hybrid Encryption Integration (~2-3 hours, 1 member)
- [ ] **Task 4.1: Port Encryption Logic**  
  *Description*: Adapt encryption for extension.  
  *Prompt*: “Port QuMail multi-level encryption (Levels 1-4) to Chrome extension JavaScript with Firebase key retrieval via Render, using email-based access.”  
  *Action*: Create `/chrome-extension/encryption.js` with functions for OTP (`/api/qkd/key`), AES (`/api/hybrid/derive`), PQC (`/api/pqc/mlkem`), plaintext. Use `fetch` for Render APIs with sender/recipient emails.  
  *Contribution*: Provides encryption capabilities.

- [ ] **Task 4.2: Implement Key Management**  
  *Description*: Handle key generation and storage.  
  *Prompt*: “Implement QuMail extension key management for QKD, ECDH, ML-KEM via Render and Firebase, using email addresses.”  
  *Action*: Fetch keys from Render (`/api/chrome/encrypt`), store in Firebase (`/keys/users/{email}/{keyId}`), retrieve for decryption with user email. Include `sender`, `recipient`, `level`.  
  *Contribution*: Enables persistent key management.

- [ ] **Task 4.3: Add Security Gauge**  
  *Description*: Display 192-bit strength gauge.  
  *Prompt*: “Inject violet/purple glassmorphism gauge in Gmail showing 192-bit strength for Levels 1-3.”  
  *Action*: Inject CSS-animated gauge in compose, update per level (192-bit for Levels 1-3, 0 for Level 4).  
  *Contribution*: Visualizes security.

- [ ] **Task 4.4: Test End-to-End Encryption**  
  *Description*: Verify encryption/decryption flow.  
  *Prompt*: “Test QuMail extension encryption/decryption in Gmail with all 4 levels and Firebase keys, using email-based access.”  
  *Action*: Send test emails, verify decryption after reload using Firebase keys. Test two users (e.g., Alice, Bob).  
  *Contribution*: Ensures reliable encryption.

## Step 5: Animations and Visual Features (~1-2 hours, 1 member)
- [ ] **Task 5.1: Port Three.js Animation**  
  *Description*: Add hybrid key animation.  
  *Prompt*: “Port QuMail Three.js animation (green QKD, purple ML-KEM, blue ECDH → violet super-key, 500 particles) for Gmail compose.”  
  *Action*: Create `/chrome-extension/animations.js`, injectබ

System: inject canvas in compose, optimize for 30-60 FPS.  
  *Contribution*: Enhances demo visual.  

- [ ] **Task 5.2: Add Security Badge Animations**  
  *Description*: Animate badges in inbox.  
  *Prompt*: “Add animated violet/purple badges to Gmail inbox for QuMail-encrypted emails.”  
  *Action*: Inject CSS animations for badges (`[QuMail Encrypted]`), indicate level (e.g., purple for Level 3).  
  *Contribution*: Visualizes encryption status.  

- [ ] **Task 5.3: Add Threat Simulation**  
  *Description*: Show security popups.  
  *Prompt*: “Add QuMail threat simulation popups in Gmail showing ‘Quantum Hacker Alert’ (Level 4) vs. ‘Hybrid Protected’ (Levels 1-3).”  
  *Action*: Inject popups with glassmorphism styling, trigger on level selection or decrypt.  
  *Contribution*: Demonstrates security benefits.  

- [ ] **Task 5.4: Optimize Animation Performance**  
  *Description*: Ensure animations don’t slow Gmail.  
  *Prompt*: “Optimize QuMail Three.js animations for minimal Gmail performance impact.”  
  *Action*: Reduce particles to ~500, cache results, test with multiple tabs in Chrome DevTools.  
  *Contribution*: Ensures smooth experience.  

## Step 6: Email Sending and Attachment Handling (~1-2 hours, 1 member)
- [ ] **Task 6.1: Implement Gmail API (Optional)**  
  *Description*: Use Gmail API for reliable sending.  
  *Prompt*: “Generate JavaScript to send QuMail encrypted emails via Gmail API, with DOM fallback, without OAuth2.”  
  *Action*: Use DOM injection (`click` Gmail send button), format MIME package with `X-QuMail-KeyID`. Fallback to Gmail API if needed (optional).  
  *Contribution*: Enhances email reliability.  

- [ ] **Task 6.2: Handle Email Attachments**  
  *Description*: Encrypt/decrypt attachments.  
  *Prompt*: “Generate JavaScript to handle QuMail email attachments using MIME in Gmail.”  
  *Action*: Port MIME logic from Electron app, encrypt attachments with selected level, include in MIME package with `Content-Disposition: attachment`.  
  *Contribution*: Supports full email functionality.  

- [ ] **Task 6.3: Format Encrypted Email**  
  *Description*: Create MIME package.  
  *Prompt*: “Generate JavaScript to format QuMail encrypted emails with MIME, including key IDs and ‘[QuMail Encrypted]’ marker.”  
  *Action*: Add headers (`X-QuMail-KeyID: key_172`, `Subject: [QuMail Encrypted]`), encode body as base64.  
  *Contribution*: Ensures email compatibility.  

- [ ] **Task 6.4: Test Email Flow**  
  *Description*: Verify send/receive with attachments.  
  *Prompt*: “Test QuMail extension email send/receive with attachments in Gmail for all levels, using email-based access.”  
  *Action*: Test with personal/Workspace accounts, verify encryption/decryption, attachments, toggle on/off. Use two users (e.g., Alice, Bob).  
  *Contribution*: Validates email flow.  

## Step 7: Testing and Demo Preparation (~2-3 hours, Team)
- [ ] **Task 7.1: Comprehensive Testing**  
  *Description*: Test all features and configurations.  
  *Prompt*: “Generate test suite for QuMail extension covering encryption, Gmail integration, Firebase keys, and attachments without OAuth2.”  
  *Action*: Test with personal/Workspace accounts, Chrome/Edge, email sizes, attachments. Use Playwright for automation.  
  *Contribution*: Ensures reliability.  

- [ ] **Task 7.2: Chrome Web Store Package**  
  *Description*: Prepare extension for distribution.  
  *Prompt*: “Package QuMail extension for Chrome Web Store with violet/purple icons and screenshots.”  
  *Action*: Create icons (16x16, 48x48, 128x128) in Canva, write store description (quantum security, Gmail integration), take Gmail screenshots.  
  *Contribution*: Prepares distribution.  

- [ ] **Task 7.3: Sideload for Demo**  
  *Description*: Prepare sideloading for judges.  
  *Prompt*: “Generate instructions to sideload QuMail extension for hackathon demo.”  
  *Action*: Zip `/chrome-extension`, provide guide for `chrome://extensions` loading, test with team.  
  *Contribution*: Ensures demo access.  

- [ ] **Task 7.4: Security and Privacy Review**  
  *Description*: Ensure compliance with Chrome Web Store.  
  *Prompt*: “Review QuMail extension for Chrome Web Store security and privacy compliance, focusing on Firebase and Render data handling.”  
  *Action*: Minimize permissions (`tabs`, `storage`, `scripting`, `webRequest`), add privacy policy (Firebase/Render data handling).  
  *Contribution*: Meets store requirements.  

- [ ] **Task 7.5: Create Demo Script**  
  *Description*: Plan 2-3 minute demo.  
  *Prompt*: “Create 2-3 minute demo script for QuMail extension showing Gmail integration, encryption, animations, and Firebase persistence without OAuth2.”  
  *Action*: Plan flow: Install → toggle → encrypt email (Level 2) → show animation → decrypt → show Firebase keys. Save in `/docs/demo.md`.  
  *Contribution*: Ensures polished demo.  

- [ ] **Task 7.6: Document Architecture**  
  *Description*: Update project documentation.  
  *Prompt*: “Document QuMail extension architecture with Manifest V3, Gmail integration, Render, Firebase, and email-based key access.”  
  *Action*: Create `/chrome-extension/README.md` with diagrams (Manifest, Render, Firebase), installation, troubleshooting.  
  *Contribution*: Provides clear documentation.  

## Architecture Overview

### **Extension Structure**:
```
chrome-extension/
├── manifest.json                 # Manifest V3 configuration
├── background.js                 # Service worker for API communication
├── popup.html                    # Popup interface
├── popup.js                      # Popup functionality
├── animations.js                 # Three.js animations
├── encryption.js                 # Encryption logic
├── content-scripts/
│   ├── gmail-injector.js         # Gmail UI injection
│   ├── gmail-compose.js          # Compose window logic
│   ├── gmail-read.js             # Inbox decryption logic
│   └── message-passing.js        # Component communication
├── styles/
│   ├── popup.css                 # Popup styling
│   └── gmail-integration.css     # Gmail UI styling
└── icons/
    ├── icon16.png                # Extension icons
    ├── icon48.png
    └── icon128.png
```

### **Backend Updates**:
```
backend/
├── app.py                       # Chrome extension endpoints
├── config.py                    # Production configuration
├── encryption.py                # Updated for Firebase
├── requirements.txt             # Production dependencies
├── render.yaml                  # Render deployment config
└── firebase_migration.py        # Firebase storage updates
```

### **Firebase Database Structure**:
```
{
  "keys": {
    "users": {
      "{email}": {
        "{keyId}": {
          "sender": "alice@gmail.com",
          "recipient": "bob@gmail.com",
          "level": 1-4,
          "key_data": "base64",
          "created_at": "timestamp"
        }
      }
    }
  }
}
```

### **API Endpoints for Extension**:
- `POST /api/chrome/encrypt` - Encrypt email, store key (input: `{plaintext, security_level, sender_email, recipient_email}`, output: `{encrypted_data, metadata: {key_id, level}}`)
- `POST /api/chrome/decrypt` - Decrypt email (input: `{encrypted_data, key_id, user_email}`, output: `{plaintext}`)
- `GET /api/chrome/keys` - List user’s keys by email
- `DELETE /api/chrome/keys/{key_id}` - Delete specific key
- `GET /api/chrome/status` - Extension health check

## Demo Strategy (2-3 min)
1. **Installation** (15s): “Install QuMail extension, toggle it on.”
2. **Encryption** (45s): Compose email, select Level 2, show 192-bit gauge, trigger Three.js animation, click “Send Secure.”
3. **Decryption** (30s): Receive encrypted email, click “Decrypt,” show plaintext.
4. **Persistence** (15s): “Firebase keys allow decryption of old emails.”
5. **Quantum Security** (15s): “Quantum Hacker Alert” (Level 4) vs. “Hybrid Protected” (Levels 1-3).
6. **Close** (15s): “QuMail secures Gmail for ISRO’s quantum future.”

## Success Metrics
- **Technical**: Chrome Web Store compliance, Firebase persistence, all 4 levels working, Render stability, end-to-end encryption without OAuth2.
- **Demo**: 2-3 minute workflow, multi-user testing, animations, persistence shown, ISRO alignment clear.

## Risk Mitigation
- **Gmail UI Changes**: Use MutationObservers (Task 3.5).
- **Chrome Policies**: Minimize permissions (Task 7.4).
- **Firebase Costs**: Optimize reads/writes, optional cleanup (Task 1.2).
- **Render Limits**: Use keep-alive (Task 1.5), monitor ~100 requests/day.
- **Timeline**: Prioritize Tasks 1.1-1.5, 2.1-2.5, 3.1-3.5, 4.1-4.4, 5.1-5.3, 6.2-6.4, 7.1-7.6; Task 6.1 optional.

This Chrome extension transforms QuMail into a universal Gmail security solution, enabling quantum-resistant email encryption/decryption for any user with the extension, without OAuth2.