# QuMail: Quantum Secure Email Client

**Project Overview**: QuMail is a quantum-secure email client developed for ISRO’s Smart India Hackathon (Problem Statement ID 25179, Department of Space), integrating Quantum Key Distribution (QKD) with existing email protocols to enhance security while maintaining compatibility with Gmail and Yahoo Mail. It implements a novel hybrid encryption framework (arXiv 2509.10551, September 2025), combining QKD (via ETSI GS QKD 014-compliant APIs, simulated with Qiskit BB84), post-quantum cryptography (PQC: ML-KEM-768 for key encapsulation, ML-DSA-6x5 for signatures), and classical cryptography (ECDH/X25519 for key exchange, EdDSA for signatures). The framework concatenates keys via KDF2 SHA-256 for symmetric encryption (AES-256) and uses double signatures (EdDSA + ML-DSA-6x5) for authenticity, achieving 192-bit security against quantum and classical threats. Built from scratch using Cursor IDE, QuMail features a violet/purple glassmorphism UI, modularity for future chat/video suite, and a 2-3 minute demo to wow non-technical judges with animations and voice commands. It runs on Windows 10/11 using standard laptops (no heavy GPU).

**Objective**: Build a fully functional prototype in ~21-28 hours (3-5 member team, starting 9/21/2025, 08:39 AM IST), aligning with ISRO’s requirements for QKD integration, email compatibility, multi-level security, and modularity, while emphasizing our “2025 hybrid encryption breakthrough” for ISRO’s quantum vision.

**ISRO Problem Statement Alignment**:
- **Interfaces**:
  - **Key Manager (KM)**: Simulates ETSI GS QKD 014 REST-based key delivery APIs (e.g., `/api/qkd/key` returns JSON: `{"key_id": "qkd_001", "key": "<256-bit-key>", "metadata": {"length": 256, "error_rate": 0.1}}`) using Flask and Qiskit BB84 for pseudo-random key generation with 10-15% error detection.
  - **Email Servers**: Uses SMTP (sending) and IMAP (receiving) for Gmail/Yahoo, encrypting content/attachments at the application layer.
  - **Users**: Violet/purple glassmorphism GUI (frosted glass cards, transparent backgrounds, blur effects) for inputs (recipient, subject, content, attachments, encryption level).
- **Use Case**: Users exchange emails with attachments over untrusted networks (Internet) using Gmail/Yahoo, with simulated symmetric QKD keys from local KMs.
- **Multi-Level Security Configurations** (per ISRO’s exact wording):
  - **Level 1: Quantum Secure**: One-Time Pad (OTP) using QKD key.
  - **Level 2: Quantum-aided AES**: Uses hybrid key (QKD + ECDH + ML-KEM, KDF2 SHA-256) as seed for AES-256.
  - **Level 3: Hybrid PQC**: ML-KEM-768 encapsulation with double signatures (EdDSA + ML-DSA-6x5).
  - **Level 4: No Quantum Security**: Plaintext passthrough.
- **Modularity**: Architecture supports upgrades to a suite (e.g., chat/audio/video tabs).
- **Challenges**: Seamlessly integrates QKD into email infrastructure via application-layer encryption, maintaining interoperability with existing providers.
- **Preferred OS**: Windows 10/11 (Electron for GUI, Flask for backend).

**Tech Stack**:
- **Frontend**: Electron (GUI), Tailwind CSS (violet/purple glassmorphism), Three.js (animations), Web Speech API (voice).
- **Backend**: Flask (ETSI QKD 014 API), Qiskit (BB84 QKD simulation), cryptography.py (ECDH/X25519, EdDSA, AES, KDF2), liboqs-python (ML-KEM-768, ML-DSA-6x5), scikit-learn (AI selector).
- **Email**: smtplib, imaplib (Gmail/Yahoo).
- **Storage**: Firebase Realtime Database (free tier for key/config storage).
- **Utils**: pytest.
- **Hardware**: Standard laptop (Intel i5/i7, 8-16 GB RAM, integrated graphics).

**Simulations**:
- **QKD Keys**: Qiskit BB84 (256-bit keys, 10-15% error detection for eavesdropping).
- **Key Manager**: Flask API simulating ETSI GS QKD 014 (key delivery with JSON structure: key ID, key value, metadata).
- **Attacks**: Mock bit errors (10-15%) in Qiskit for threat simulation.
- **Satellite Relay**: Three.js animation of QKD key beaming.
- **Performance**: Emulate ~951 ns ML-KEM latency with `timeit`.

**Task List**: Check off tasks as completed in Cursor IDE. Each task includes a prompt to generate code and estimated time. Parallelize tasks across team members. Feed this README into Cursor with: “Understand this detailed project overview and task list for QuMail, then assist with each task one by one as I request.”

## Step 1: Project Setup and Environment Configuration (~1.5-2 hours, 1 member, CPU-only)
- [x] **Task 1: Launch Cursor IDE**  
  *Description*: Open Cursor IDE on a Windows laptop (Intel i5/i7, 8-16 GB RAM, Windows 10/11). Create a new project named "QuMail" in the current directory.  
  *Prompt*: "Create a new project in Cursor IDE for a Python/Node.js quantum email client."  
  *Action*: Click "New Project," select Python/Node.js template, set directory.  
  *Contribution*: Initializes development environment.

- [x] **Task 2: Create Folder Structure**  
  *Description*: Set up folders: `/frontend` (Electron GUI), `/backend` (Flask, encryption), `/simulator` (QKD), `/tests` (pytest), `/docs` (README).  
  *Prompt*: "Generate a project folder structure for a quantum email client with frontend, backend, simulator, tests, and docs folders."  
  *Action*: Review Cursor's structure, create folders in File Explorer or IDE.  
  *Contribution*: Organizes project for modularity.

- [x] **Task 3: Install Python Dependencies**  
  *Description*: Install Python 3.12+, then run `pip install flask cryptography pyOpenSSL qiskit liboqs-python pytest scikit-learn firebase-admin`.  
  *Prompt*: "Generate requirements.txt for a quantum email client with Flask, Qiskit, cryptography, liboqs-python, pytest, scikit-learn, firebase-admin."  
  *Action*: Save `requirements.txt` in project root, run `pip install -r requirements.txt`.  
  *Contribution*: Sets up backend dependencies.

- [x] **Task 4: Install Node.js Dependencies**  
  *Description*: Install Node.js 18+, run `npm init -y` and `npm install electron three tailwindcss`.  
  *Prompt*: "Generate package.json for an Electron app with Three.js and Tailwind CSS."  
  *Action*: Save `package.json`, run `npm install`.  
  *Contribution*: Sets up frontend dependencies.

- [x] **Task 5: Initialize Git**  
  *Description*: Set up version control for team collaboration.  
  *Prompt*: "Initialize Git repository with .gitignore for Python and Node.js."  
  *Action*: Run `git init`, add `.gitignore` (ignoring `node_modules`, `__pycache__`), commit initial structure.  
  *Contribution*: Enables version control.

- [x] **Task 6: Create README Stub**  
  *Description*: Add a basic README outlining QuMail's purpose (quantum-secure email with hybrid encryption).  
  *Prompt*: "Generate a README stub for a quantum email client with hybrid encryption."  
  *Action*: Save as `README.md` in `/docs`.  
  *Contribution*: Documents project purpose.

- [x] **Task 6.5: Set Up Firebase**  
  *Description*: Create a free Firebase project for Realtime Database storage (keys/configs).  
  *Prompt*: "Generate Python code to set up Firebase Realtime Database integration for key storage in a quantum email client."  
  *Action*: Create free Firebase account (console.firebase.google.com), add project, enable Realtime Database, save credentials (API key, database URL) in `/backend/config.py`. Install `firebase-admin` (`pip install firebase-admin`).  
  *Contribution*: Enables cloud storage for keys.

## Step 2: Frontend GUI Development (Electron with Glassmorphism UI) (~5-7 hours, 1-2 members, Minimal GPU)
- [x] **Task 7: Initialize Electron App**  
  *Description*: Create an Electron project with a main window for the email client.  
  *Prompt*: "Create an Electron app for Windows with a main window for an email client."  
  *Action*: Save generated `main.js` and `index.html` in `/frontend`. Update `package.json` with `"start": "electron ."`. Run `npm start` to verify.  
  *Contribution*: Sets up desktop GUI framework.

- [x] **Task 8: Design Glassmorphism UI**  
  *Description*: Create a layout with sidebar (inbox, sent, quantum network tabs), email list, and composition area (recipient, subject, content, attachments). Use Tailwind CSS for violet/purple glassmorphism (gradients: `bg-gradient-to-r from-purple-600 to-violet-500`, semi-transparent `bg-opacity-30`, blur `backdrop-blur-md`). Add dropdown for encryption levels: Level 1 (Quantum Secure), Level 2 (Quantum-aided AES), Level 3 (Hybrid PQC), Level 4 (No Quantum Security).  
  *Prompt*: "Generate Electron index.html with Tailwind CSS for a glassmorphism email client UI in violet/purple, including sidebar, email list, composition area (recipient, subject, content, attachments), and encryption dropdown with options: Level 1 (Quantum Secure), Level 2 (Quantum-aided AES), Level 3 (Hybrid PQC), Level 4 (No Quantum Security)."  
  *Action*: Save in `/frontend/index.html`, add Tailwind CDN (`https://cdn.tailwindcss.com`), tweak colors (`purple-600`, `violet-500`) and blur (`backdrop-filter: blur(10px)`).  
  *Contribution*: Creates futuristic UI for judges.

- [x] **Task 9: Add Starry Background**  
  *Description*: Use a starry, space-themed background with violet/purple gradient overlay.  
  *Prompt*: "Generate CSS for a starry space background in Electron, styled for ISRO theme with violet/purple accents."  
  *Action*: Download free starry image from Unsplash, save in `/frontend/assets`, add CSS to `index.html` (e.g., `background: url('stars.jpg')` with `bg-gradient-to-b from-purple-800/30`).  
  *Contribution*: Enhances ISRO alignment.

- [x] **Task 10: Implement Mock API Calls**  
  *Description*: Simulate QKD key retrieval (ETSI GS QKD 014 format: `{"key_id": "qkd_001", "key": "<256-bit-key>", "metadata": {"length": 256, "error_rate": 0.1}}`) with static JSON.  
  *Prompt*: "Add mock fetch calls in Electron to simulate ETSI GS QKD 014 key retrieval with JSON structure including key_id, key, and metadata."  
  *Action*: Add JavaScript in `/frontend/renderer.js` to log/display mock keys in GUI.  
  *Contribution*: Enables early GUI testing.

- [x] **Task 11: Add Placeholder Animations**  
  *Description*: Add temporary CSS animations (e.g., violet/purple spinning loader) for hybrid key flows.  
  *Prompt*: "Generate CSS animations for a placeholder QKD key flow in Electron, using violet/purple colors."  
  *Action*: Add to `index.html` (e.g., `@keyframes glow { from { box-shadow: 0 0 10px violet; } }`).  
  *Contribution*: Previews animation for judges.

- [x] **Task 12: Test GUI with Mock Data**  
  *Description*: Simulate email sending by logging form inputs and mock encrypted output.  
  *Prompt*: "Generate test script for Electron GUI with mock email sending."  
  *Action*: Save in `/frontend/test_gui.js`, run `npm start`, verify form inputs and animations.  
  *Contribution*: Ensures functional GUI for demo.

## Step 3: Exaggerated Frontend Features (~5-7 hours, 1-2 members, Minimal GPU)
- [x] **Task 13: Hybrid Key Visualization (Three.js)**  
  *Description*: Create a Three.js animation showing QKD (green particles), ML-KEM (purple particles), and ECDH (blue particles) merging into a violet “super-key” on a glassmorphism card.  
  *Prompt*: “Generate Three.js animation in Electron for hybrid QKD-ML-KEM-ECDH key derivation, with green (QKD), purple (ML-KEM), blue (ECDH) particles merging into a violet key, styled with glassmorphism.”  
  *Action*: Add Three.js CDN to `index.html`, create canvas, write animation in `/frontend/renderer.js` (1000 particles, 30-60 FPS). Tweak for violet/purple glow.  
  *Contribution*: Visualizes novel hybrid encryption.

- [x] **Task 14: Security Gauge**  
  *Description*: Add a violet/purple glassmorphism gauge showing “Hybrid Strength: 192-bit” (green for Level 1, blue for Level 2, purple for Level 3).  
  *Prompt*: “Create Tailwind CSS gauge in Electron for hybrid encryption levels (Level 1: Quantum Secure, Level 2: Quantum-aided AES, Level 3: Hybrid PQC), styled with violet/purple glassmorphism, showing 192-bit strength.”  
  *Action*: Add HTML/CSS to `index.html`, JavaScript in `renderer.js` to update gauge based on dropdown.  
  *Contribution*: Highlights hybrid security strength.

- [ ] **Task 15: Voice Assistant (Web Speech API)**  
  *Description*: Enable voice commands (e.g., “Select Level 2 encryption,” “Send secure email”) with feedback on a violet/purple glassmorphism card.  
  *Prompt*: “Integrate Web Speech API in Electron for voice commands tied to encryption levels (Level 1: Quantum Secure, Level 2: Quantum-aided AES, Level 3: Hybrid PQC), displayed on a violet/purple glassmorphism card.”  
  *Action*: Add JavaScript in `renderer.js`, test commands (e.g., update dropdown).  
  *Contribution*: Adds interactive demo feature.

- [ ] **Task 16: Threat Simulation**  
  *Description*: Add a button for red “Quantum Hacker Alert” popup (Level 4: No Quantum Security) vs. violet/purple glassmorphism “Hybrid Protected” badge with signature verification (Levels 1-3).  
  *Prompt*: “Create red/green popups in Electron for hybrid threat simulation, styled with violet/purple glassmorphism for the protected badge (Levels 1-3).”  
  *Action*: Add HTML/JavaScript in `index.html`/`renderer.js`, link to button clicks.  
  *Contribution*: Contrasts hybrid security for judges.

- [ ] **Task 17: Satellite Relay Animation**  
  *Description*: Animate a satellite beaming QKD keys on a 3D globe (violet/purple accents) in a “Quantum Network” tab.  
  *Prompt*: “Generate Three.js animation for satellite QKD relay on a globe in Electron, styled with violet/purple glassmorphism for ISRO.”  
  *Action*: Add tab in `index.html`, implement animation in `renderer.js`.  
  *Contribution*: Ties to ISRO’s space-tech vision.

- [ ] **Task 18: Mock AI Encryption Selector**  
  *Description*: Display mock suggestions (e.g., “Use Level 3: Hybrid PQC for confidential emails”) on a glassmorphism card.  
  *Prompt*: “Add mock AI encryption suggestion in Electron GUI, recommending Level 1, 2, or 3, displayed on a violet/purple glassmorphism card.”  
  *Action*: Add JavaScript in `renderer.js` with static rules (e.g., keyword “confidential”).  
  *Contribution*: Previews AI feature for demo.

- [ ] **Task 19: Test Animations and Voice**  
  *Description*: Verify Three.js animations (smoothness), voice commands (accuracy), and popups.  
  *Prompt*: “Generate test script for Three.js animations and Web Speech API in Electron.”  
  *Action*: Save in `/frontend/test_animations.js`, run tests, reduce particle count (e.g., to 500) if laggy.  
  *Contribution*: Ensures smooth demo visuals.

## Step 4: Backend - Simulate Key Manager (KM) for QKD (~3-4 hours, 1 member, CPU-only)
- [x] **Task 20: Create Flask App**  
  *Description*: Set up a Flask server with a `/api/qkd/key` endpoint conforming to ETSI GS QKD 014 (JSON: key_id, key, metadata).  
  *Prompt*: “Generate Flask server for a quantum email client with a REST endpoint for ETSI GS QKD 014 key delivery, returning JSON with key_id, 256-bit key, and metadata (length, error_rate).”  
  *Action*: Save in `/backend/app.py`, run locally (`flask run`).  
  *Contribution*: Enables ETSI-compliant key delivery.

- [x] **Task 21: Simulate QKD Keys**  
  *Description*: Use Qiskit for BB84 protocol simulation (256-bit keys with 10-15% error detection).  
  *Prompt*: “Generate Qiskit code for BB84 QKD simulation with 256-bit key output and 10-15% error detection for eavesdropping, formatted for ETSI GS QKD 014 JSON.”  
  *Action*: Save in `/simulator/qkd.py`, integrate with Flask endpoint, store keys in Firebase.  
  *Contribution*: Simulates QKD for hybrid framework.

- [x] **Task 22: Add ECDH/X25519 Key Exchange**  
  *Description*: Generate ECDH shared secret using X25519 curve.  
  *Prompt*: “Generate Python code for ECDH/X25519 key exchange using cryptography.py.”  
  *Action*: Save in `/backend/crypto.py`, call from Flask, store shared secret in Firebase.  
  *Contribution*: Adds classical crypto to hybrid.

- [x] **Task 23: Add ML-KEM-768 Encapsulation**  
  *Description*: Implement post-quantum key encapsulation (ML-KEM-768).  
  *Prompt*: “Generate Python code for ML-KEM-768 key encapsulation using liboqs-python.”  
  *Action*: Save in `/backend/crypto.py`, combine with QKD/ECDH, store in Firebase.  
  *Contribution*: Adds PQC to hybrid framework.

- [x] **Task 24: Derive Hybrid Key**  
  *Description*: Concatenate QKD, ECDH, and ML-KEM shared secrets, derive 256-bit key with KDF2 SHA-256.  
  *Prompt*: “Generate Python code to concatenate QKD, ECDH, ML-KEM keys and derive a 256-bit key with KDF2 SHA-256, storing in Firebase.”  
  *Action*: Add to `/backend/crypto.py`, test key length.  
  *Contribution*: Creates novel hybrid key.

- [x] **Task 25: Add mTLS Authentication**  
  *Description*: Secure Flask API with mTLS (self-signed certificates for demo).  
  *Prompt*: “Generate Flask code with mTLS authentication using pyOpenSSL for an ETSI GS QKD 014 API.”  
  *Action*: Generate certs, configure Flask in `app.py`.  
  *Contribution*: Secures QKD key delivery.

- [x] **Task 26: Test API**  
  *Description*: Verify ETSI GS QKD 014 key retrieval with curl and pytest.  
  *Prompt*: “Generate pytest and curl commands for testing a Flask ETSI GS QKD 014 API.”  
  *Action*: Save in `/tests/test_qkd.py`, run `pytest`.  
  *Contribution*: Ensures reliable QKD API.

## Step 5: Backend - Multi-Level Hybrid Encryption Module (~4-5 hours, 1 member, CPU-only)
- [x] **Task 27: Create Encryption Module**  
  *Description*: Set up a modular Python class for encryption (Levels 1-4).  
  *Prompt*: “Generate a Python class for multi-level encryption with Level 1: Quantum Secure (OTP), Level 2: Quantum-aided AES, Level 3: Hybrid PQC, Level 4: No Quantum Security.”  
  *Action*: Save in `/backend/encryption.py`.  
  *Contribution*: Enables multi-level security.

- [x] **Task 28: Level 1: Quantum Secure (OTP)**  
  *Description*: Implement XOR-based OTP using QKD key from Firebase.  
  *Prompt*: “Generate Python code for OTP encryption with a QKD key from Firebase Realtime Database.”  
  *Action*: Add to `encryption.py`, test with sample text.  
  *Contribution*: Provides quantum-secure encryption.

- [ ] **Task 29: Level 2: Quantum-aided AES**  
  *Description*: Use hybrid-derived key (QKD + ECDH + ML-KEM, KDF2 SHA-256) from Firebase for AES-256.  
  *Prompt*: “Generate Python code for AES-256 encryption using a hybrid QKD-ML-KEM-ECDH key derived with KDF2 SHA-256 from Firebase.”  
  *Action*: Use `cryptography.fernet`, add to `encryption.py`.  
  *Contribution*: Combines hybrid key for AES.

- [ ] **Task 30: Level 3: Hybrid PQC**  
  *Description*: Implement ML-KEM-768 encapsulation with double signatures (EdDSA + ML-DSA-6x5).  
  *Prompt*: “Generate Python code for ML-KEM-768 encapsulation with EdDSA and ML-DSA-6x5 double signatures using liboqs-python and cryptography.py.”  
  *Action*: Add to `encryption.py`, verify signatures.  
  *Contribution*: Adds PQC with novel authenticity.

- [ ] **Task 31: Level 4: No Quantum Security**  
  *Description*: Add plaintext passthrough.  
  *Prompt*: “Generate Python code for a plaintext email option (Level 4: No Quantum Security).”  
  *Action*: Add to `encryption.py`.  
  *Contribution*: Completes encryption levels.

- [ ] **Task 32: Handle Attachments**  
  *Description*: Encrypt attachments with hybrid keys using MIME.  
  *Prompt*: “Generate Python code to encrypt email attachments with hybrid keys from Firebase using MIME.”  
  *Action*: Add to `encryption.py`.  
  *Contribution*: Secures attachments.

- [ ] **Task 33: Test Encryption**  
  *Description*: Verify all levels and signatures.  
  *Prompt*: “Generate pytest for hybrid encryption/decryption (Levels 1-4), including double signatures.”  
  *Action*: Save in `/tests/test_encryption.py`, run `pytest`.  
  *Contribution*: Ensures robust encryption.

## Step 6: Email Integration (SMTP/IMAP) (~3-4 hours, 1 member, CPU-only)
- [ ] **Task 34: Send Emails with smtplib**  
  *Description*: Apply hybrid encryption (Levels 1-3) before sending.  
  *Prompt*: “Generate Python code for Gmail SMTP with hybrid encryption (Level 1: Quantum Secure, Level 2: Quantum-aided AES, Level 3: Hybrid PQC) applied to content and attachments.”  
  *Action*: Save in `/backend/email.py`, integrate with `encryption.py`.  
  *Contribution*: Enables secure email sending.

- [ ] **Task 35: Receive Emails with imaplib**  
  *Description*: Decrypt and verify signatures for Levels 1-3.  
  *Prompt*: “Generate Python code for Gmail IMAP with hybrid decryption and EdDSA/ML-DSA signature verification for Levels 1-3.”  
  *Action*: Add to `email.py`.  
  *Contribution*: Enables secure email receiving.

- [ ] **Task 36: Add KM/Email Login**  
  *Description*: Use App Passwords for Gmail (OAuth optional).  
  *Prompt*: “Generate Python code for Gmail App Password login in smtplib/imaplib.”  
  *Action*: Add login prompts in GUI and backend.  
  *Contribution*: Secures email access.

- [ ] **Task 37: Test Email Flow**  
  *Description*: Use dummy Gmail accounts for end-to-end testing.  
  *Prompt*: “Generate tests for end-to-end email send/receive with hybrid security (Levels 1-3).”  
  *Action*: Save in `/tests/test_email.py`, test with dummy accounts.  
  *Contribution*: Verifies email functionality.

## Step 7: AI Encryption Selector (~2-3 hours, 1 member, Optional, CPU-only)
- [ ] **Task 38: Implement Keyword Analysis**  
  *Description*: Use scikit-learn for basic NLP (e.g., “confidential” triggers Level 3: Hybrid PQC).  
  *Prompt*: “Generate scikit-learn model for email content analysis to suggest encryption levels (Level 1: Quantum Secure, Level 2: Quantum-aided AES, Level 3: Hybrid PQC).”  
  *Action*: Save in `/backend/ai_selector.py`.  
  *Contribution*: Adds smart encryption feature.

- [ ] **Task 39: Integrate with GUI**  
  *Description*: Display suggestions on a violet/purple glassmorphism card.  
  *Prompt*: “Generate JavaScript to display scikit-learn AI suggestions (Level 1-3) in Electron GUI on a violet/purple glassmorphism card.”  
  *Action*: Add to `renderer.js`.  
  *Contribution*: Enhances demo interactivity.

- [ ] **Task 40: Test AI**  
  *Description*: Verify suggestions with sample emails.  
  *Prompt*: “Generate test cases for AI encryption selector recommending Levels 1-3.”  
  *Action*: Save in `/tests/test_ai.py`, run `pytest`.  
  *Contribution*: Ensures AI reliability.

## Step 8: Modularity for Application Suite (~1-2 hours, 1 member, CPU-only)
- [ ] **Task 41: Add Mock Suite Tabs**  
  *Description*: Create GUI tabs for mock chat/video with violet/purple glassmorphism.  
  *Prompt*: “Generate Electron HTML for mock chat and video tabs, styled with violet/purple glassmorphism.”  
  *Action*: Add to `index.html`.  
  *Contribution*: Shows scalability.

- [ ] **Task 42: Modularize Encryption**  
  *Description*: Refactor encryption for reuse across applications.  
  *Prompt*: “Refactor Python hybrid encryption module into a reusable class for Level 1: Quantum Secure, Level 2: Quantum-aided AES, Level 3: Hybrid PQC.”  
  *Action*: Update `encryption.py`.  
  *Contribution*: Enables future suite expansion.

## Step 9: Testing and Debugging (~2-3 hours, Team, CPU-only)
- [ ] **Task 43: Test Hybrid Components**  
  *Description*: Cover QKD, encryption (Levels 1-3), signatures, email.  
  *Prompt*: “Generate pytest suite for QKD simulation (ETSI GS QKD 014), hybrid encryption (Levels 1-3), double signatures, and email flow.”  
  *Action*: Save in `/tests`, run `pytest`.  
  *Contribution*: Ensures robust functionality.

- [ ] **Task 44: Debug Issues**  
  *Description*: Fix errors (e.g., key mismatches, animation lag).  
  *Prompt*: “Fix errors in hybrid key derivation or Electron-Flask integration for ETSI QKD 014 API.”  
  *Action*: Apply Cursor’s suggested fixes.  
  *Contribution*: Resolves demo glitches.

- [ ] **Task 45: Simulate Attacks**  
  *Description*: Inject bit errors for QKD eavesdropping demo.  
  *Prompt*: “Generate Qiskit code to simulate eavesdropping with 10-15% bit errors for BB84 QKD.”  
  *Action*: Add to `/simulator/qkd.py`, link to threat popup.  
  *Contribution*: Enhances demo contrast.

## Step 10: Demo and PPT Preparation (~2-3 hours, Team, Minimal GPU)
- [ ] **Task 46: Create Intro Video**  
  *Description*: Make a 15-second video in Canva/Blender showing hybrid key flows (violet/purple theme).  
  *Prompt*: “Generate HTML to embed a 15-second intro video in Electron.”  
  *Action*: Create video in Canva (free tier), embed in `index.html`.  
  *Contribution*: Sets cinematic demo tone.

- [ ] **Task 47: Rehearse Demo**  
  *Description*: Plan 2-3 min demo: Live email send, hybrid animation, voice command, threat contrast, satellite relay.  
  *Prompt*: “Generate a 2-3 minute demo narrative for a hybrid quantum email client with ETSI QKD 014 and Levels 1-3 encryption.”  
  *Action*: Save narrative, rehearse with team.  
  *Contribution*: Ensures polished presentation.

- [ ] **Task 48: Create PPT**  
  *Description*: Use violet/purple glassmorphism theme, slides: Title, Problem, Solution, Novel Hybrid Innovation, ISRO Impact.  
  *Prompt*: “Generate Google Slides template with violet/purple glassmorphism theme for a quantum email client.”  
  *Action*: Save slides in Google Slides (free), add GUI/animation screenshots.  
  *Contribution*: Communicates novelty to judges.

## Step 11: Final Polish and Assumptions (~1 hour, Team, CPU-only)
- [ ] **Task 49: Confirm Assumptions**  
  *Description*: Document simulated QKD (no hardware), dummy emails, symmetric keys.  
  *Action*: Update this README with assumptions section.  
  *Contribution*: Clarifies demo scope.

- [ ] **Task 50: Optimize for Windows**  
  *Description*: Test Electron build for Windows compatibility.  
  *Prompt*: “Generate script to ensure Electron app runs on Windows with Flask ETSI QKD 014 API.”  
  *Action*: Run `npm start`, verify no crashes.  
  *Contribution*: Ensures demo reliability.

- [ ] **Task 51: Document Project**  
  *Description*: Update README with hybrid framework overview.  
  *Prompt*: “Generate README for a hybrid quantum email client with violet/purple glassmorphism UI and ETSI GS QKD 014 compliance.”  
  *Action*: Update this file with final details.  
  *Contribution*: Completes documentation.

## Assumptions
- **Simulated QKD**: Qiskit BB84 (no hardware) for ETSI GS QKD 014-compliant keys.
- **Dummy Emails**: Gmail/Yahoo accounts with App Passwords.
- **Symmetric Keys**: Pre-shared for demo simplicity.
- **No Heavy GPU**: Runs on standard laptop (Intel i5/i7, 8-16 GB RAM, integrated graphics).
- **Free Tools**: Cursor IDE (free tier), Firebase (free tier), Canva (free tier), Google Slides, Unsplash images.
- **No Docker**: Flask runs locally (`flask run`) for simplicity.

## Demo Strategy (2-3 min)
- **Intro**: Play 15-second Canva video: “QuMail stops quantum hackers with hybrid shields.”
- **Live Email**: Send Gmail with Level 2: Quantum-aided AES, show violet/purple glassmorphism UI.
- **Animation**: Display Three.js hybrid key flow (green/QKD, purple/ML-KEM, blue/ECDH).
- **Voice Command**: Say “Select Level 3 encryption,” update gauge (192-bit strength).
- **Threat Contrast**: Show red “Quantum Hacker Alert” (Level 4) vs. violet “Hybrid Protected” badge (Levels 1-3).
- **Satellite Relay**: Show Three.js globe animation for ISRO tie-in.
- **Pitch**: “Our 2025 hybrid encryption, compliant with ETSI GS QKD 014, combines quantum, post-quantum, and classical layers for unbreakable email security, scalable for ISRO’s quantum future.”