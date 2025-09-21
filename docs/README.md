# QuMail Documentation

## Project Overview

QuMail is a quantum-secure email client developed for ISRO's Smart India Hackathon 2025 (Problem Statement ID: 25179). It integrates Quantum Key Distribution (QKD) with existing email protocols while maintaining compatibility with Gmail and Yahoo Mail.

## Core Innovation

### Hybrid Encryption Framework
Our novel 2025 hybrid encryption framework combines three cryptographic layers:

1. **Quantum Layer**: QKD via ETSI GS QKD 014-compliant APIs (simulated with Qiskit BB84)
2. **Post-Quantum Layer**: ML-KEM-768 (key encapsulation) + ML-DSA-6x5 (digital signatures)  
3. **Classical Layer**: ECDH/X25519 (key exchange) + EdDSA (signatures)

### Security Achievement
- **192-bit security** against both quantum and classical threats
- **KDF2 SHA-256** key concatenation for symmetric encryption (AES-256)
- **Double signatures** (EdDSA + ML-DSA-6x5) for authenticity

## Multi-Level Security Configurations

- **Level 1: Quantum Secure** - One-Time Pad (OTP) using QKD key
- **Level 2: Quantum-aided AES** - Uses hybrid key (QKD + ECDH + ML-KEM) as seed for AES-256
- **Level 3: Hybrid PQC** - ML-KEM-768 encapsulation with double signatures
- **Level 4: No Quantum Security** - Plaintext passthrough

## Technical Architecture

### Frontend
- **Electron**: Desktop GUI framework
- **Tailwind CSS**: Violet/purple glassmorphism styling
- **Three.js**: 3D particle animations for key visualization
- **Web Speech API**: Voice command integration

### Backend  
- **Flask**: ETSI GS QKD 014 API simulation
- **Qiskit**: BB84 QKD protocol simulation
- **cryptography.py**: ECDH/X25519, EdDSA, AES, KDF2
- **liboqs-python**: ML-KEM-768, ML-DSA-6x5
- **Firebase Realtime Database**: Key and configuration storage

## Demo Features

1. **Hybrid Key Visualization**: Three.js animation showing green (QKD), purple (ML-KEM), and blue (ECDH) particles merging
2. **Security Gauge**: Real-time 192-bit strength indicator
3. **Voice Commands**: "Select Level 2 encryption", "Send secure email"
4. **Threat Simulation**: Red "Quantum Hacker Alert" vs violet "Hybrid Protected" badges
5. **Satellite Relay Animation**: 3D globe for ISRO space-tech alignment

## ISRO Alignment

- **ETSI GS QKD 014 compliance** for key delivery APIs
- **Gmail/Yahoo integration** via SMTP/IMAP
- **Application-layer encryption** maintaining interoperability
- **Modular architecture** for future communication suite expansion
- **Windows 10/11 compatibility** with standard laptops

## Development Status

This project follows a comprehensive 51-task roadmap across 11 development phases. Current progress tracked in `tasks.markdown`.

## Future Vision

QuMail serves as the foundation for a complete quantum-secure communication suite, with planned expansions to chat, audio, and video applications using the same hybrid encryption framework.
