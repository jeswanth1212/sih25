# 🛡️ QuMail: Quantum Secure Email Client

<div align="center">

![QuMail Logo](https://img.shields.io/badge/QuMail-Quantum%20Secure-blueviolet?style=for-the-badge&logo=shield&logoColor=white)
![ISRO SIH 2025](https://img.shields.io/badge/ISRO-SIH%202025-orange?style=for-the-badge&logo=rocket&logoColor=white)
![Problem Statement](https://img.shields.io/badge/Problem%20ID-25179-blue?style=for-the-badge)

**Revolutionary Quantum-Secure Email Client for ISRO's Smart India Hackathon 2025**

*Combining Quantum Key Distribution, Post-Quantum Cryptography, and Classical Encryption*

</div>

---

## 🌟 **Project Overview**

QuMail is a **quantum-secure email client** developed for ISRO's Smart India Hackathon 2025 (Problem Statement ID: 25179). It integrates **Quantum Key Distribution (QKD)** with existing email protocols while maintaining compatibility with Gmail and Yahoo Mail.

### 🚀 **Novel Hybrid Encryption Framework**

Our **2025 breakthrough hybrid encryption** combines three cryptographic layers:

- **🔮 Quantum Layer**: QKD via ETSI GS QKD 014-compliant APIs (simulated with Qiskit BB84)
- **🛡️ Post-Quantum Layer**: ML-KEM-768 (key encapsulation) + ML-DSA-6x5 (digital signatures)
- **🔐 Classical Layer**: ECDH/X25519 (key exchange) + EdDSA (signatures)

**Result**: 🎯 **192-bit security** against both quantum and classical threats!

---

## 🎨 **Key Features**

### 🔐 **Multi-Level Security Configurations**
- **Level 1**: 🟢 Quantum Secure (One-Time Pad using QKD key)
- **Level 2**: 🔵 Quantum-aided AES (Hybrid key as AES-256 seed)
- **Level 3**: 🟣 Hybrid PQC (ML-KEM-768 with double signatures)
- **Level 4**: 🔴 No Quantum Security (Plaintext passthrough)

### 🎭 **Stunning Glassmorphism UI**
- **Violet/Purple theme** with space-inspired design
- **Frosted glass effects** and transparent backgrounds
- **Three.js animations** for hybrid key visualization
- **Voice commands** via Web Speech API

### 🛰️ **ISRO-Aligned Features**
- **Satellite relay animation** on 3D globe
- **ETSI GS QKD 014** standard compliance
- **Gmail/Yahoo integration** via SMTP/IMAP
- **Modular architecture** for future communication suite

---

## 🛠️ **Tech Stack**

### **Frontend** 🎨
```
Electron       Desktop GUI framework
Tailwind CSS   Violet/purple glassmorphism styling
Three.js       3D particle animations
Web Speech API Voice command integration
```

### **Backend** ⚙️
```
Flask              ETSI QKD 014 API simulation
Qiskit             BB84 QKD protocol simulation
cryptography.py    ECDH/X25519, EdDSA, AES, KDF2
liboqs-python      ML-KEM-768, ML-DSA-6x5
Firebase           Realtime Database for keys
```

### **AI & Testing** 🧠
```
scikit-learn   Smart encryption level selection
pytest         Comprehensive testing framework
```

---

## 📁 **Project Structure**

```
sih25/
├── 🎨 frontend/          # Electron GUI components
├── ⚙️ backend/           # Flask API & encryption modules
├── 🔬 simulator/         # QKD simulation with Qiskit
├── 🧪 tests/            # Test suites
├── 📚 docs/             # Documentation
├── 📋 requirements.txt   # Python dependencies
├── 📦 package.json      # Node.js configuration
├── 🚫 .gitignore        # Git ignore rules
└── 📖 tasks.markdown    # Detailed project roadmap
```

---

## 🚀 **Quick Start**

### **Prerequisites**
- Python 3.12+ 🐍
- Node.js 18+ 📦
- Windows 10/11 💻
- Standard laptop (Intel i5/i7, 8-16 GB RAM) 

### **Installation**

1. **Clone the repository**
   ```bash
   git clone https://github.com/jeswanth1212/sih25.git
   cd sih25
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Node.js dependencies**
   ```bash
   npm install
   ```

4. **Start the application**
   ```bash
   # Backend (Flask API)
   cd backend
   python app.py

   # Frontend (Electron GUI)
   cd ../frontend
   npm start
   ```

---

## 🎬 **Demo Features**

### 🔮 **Hybrid Key Visualization**
Watch **green (QKD)**, **purple (ML-KEM)**, and **blue (ECDH)** particles merge into a **violet super-key**!

### 🗣️ **Voice Commands**
- *"Select Level 2 encryption"*
- *"Send secure email"*
- *"Show quantum network"*

### 🚨 **Threat Simulation**
- **Red Alert**: "Quantum Hacker Detected!" (Level 4)
- **Violet Shield**: "Hybrid Protected" (Levels 1-3)

### 🛰️ **Satellite Relay Animation**
3D globe showing QKD key beaming via satellite for ISRO alignment

---

## 🏗️ **Development Roadmap**

Our project follows a **51-task roadmap** across **11 development phases**:

✅ **Step 1**: Project Setup (Tasks 1-5) - **COMPLETED**
🔄 **Step 2**: Frontend GUI Development (Tasks 7-12)
⏳ **Step 3**: Advanced Frontend Features (Tasks 13-19)
⏳ **Step 4**: Backend QKD Simulation (Tasks 20-26)
⏳ **Step 5**: Hybrid Encryption Module (Tasks 27-33)

*Full roadmap available in [tasks.markdown](tasks.markdown)*

---

## 🎯 **ISRO Problem Statement Alignment**

| Requirement | ✅ Implementation |
|-------------|------------------|
| **QKD Integration** | ETSI GS QKD 014-compliant Flask API |
| **Email Compatibility** | Gmail/Yahoo SMTP/IMAP integration |
| **Multi-Level Security** | 4 configurable encryption levels |
| **Modularity** | Extensible architecture for chat/video |
| **Windows Compatibility** | Electron app for Windows 10/11 |

---

## 🏆 **Innovation Highlights**

### 🔬 **World's First Hybrid Framework**
- **Concatenated key derivation** using KDF2 SHA-256
- **Double signature authentication** (EdDSA + ML-DSA-6x5)
- **Seamless QKD integration** with existing email infrastructure

### 🎨 **Judge-Winning Demo**
- **2-3 minute presentation** with live email sending
- **Cinematic animations** and voice interactions
- **Real-time threat detection** simulations

---

## 👥 **Team**

**QuMail Team SIH2025** - Developing the future of quantum-secure communications

---

## 📜 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 **Contributing**

We welcome contributions! Please read our contributing guidelines and feel free to submit pull requests.

---

## 📞 **Contact**

For questions about this project or collaboration opportunities:
- 📧 Email: qumail.team@hackathon.com
- 🐙 GitHub: [https://github.com/jeswanth1212/sih25](https://github.com/jeswanth1212/sih25)

---

<div align="center">

**🚀 Built for ISRO's Vision of Quantum-Secure Space Communications 🛰️**

*"Our 2025 hybrid encryption combines quantum, post-quantum, and classical layers for unbreakable email security, scalable for ISRO's quantum future."*

</div>
