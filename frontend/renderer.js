// QuMail Quantum Key Distribution Mock API - ETSI GS QKD 014 Compliant
// Renderer Process for Electron App

class QuantumKeyManager {
    constructor() {
        this.apiBaseUrl = 'http://localhost:8080/api/v1/qkd'; // Mock QKD API endpoint
        this.keyCache = new Map();
        this.isConnected = false;
        this.initializeEventListeners();
        this.startQKDSimulation();
    }

    // Generate mock 256-bit quantum key (64 hex characters)
    generateQuantumKey() {
        const hexChars = '0123456789abcdef';
        let key = '';
        for (let i = 0; i < 64; i++) {
            key += hexChars[Math.floor(Math.random() * 16)];
        }
        return key;
    }

    // Generate realistic QKD metadata according to ETSI GS QKD 014
    generateQKDMetadata() {
        return {
            length: 256,
            error_rate: Math.random() * 0.15, // 0-15% QBER (Quantum Bit Error Rate)
            generation_time: new Date().toISOString(),
            protocol: "BB84",
            security_level: Math.floor(Math.random() * 4) + 1, // 1-4 security levels
            entanglement_fidelity: 0.85 + Math.random() * 0.14, // 85-99% fidelity
            key_extraction_efficiency: 0.7 + Math.random() * 0.29, // 70-99% efficiency
            distance_km: Math.floor(Math.random() * 100) + 1, // 1-100 km
            channel_loss_db: Math.random() * 10, // 0-10 dB loss
        };
    }

    // Mock ETSI GS QKD 014 compliant key retrieval
    async retrieveQuantumKey(keyId = null) {
        try {
            // Simulate network delay
            await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 300));
            
            const qkdResponse = {
                key_id: keyId || `qkd_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
                key: this.generateQuantumKey(),
                metadata: this.generateQKDMetadata(),
                status: "READY",
                timestamp: new Date().toISOString(),
                qkd_node_id: "ISRO_QKD_NODE_001",
                peer_node_id: "RECIPIENT_NODE_" + Math.floor(Math.random() * 100),
            };

            // Cache the key
            this.keyCache.set(qkdResponse.key_id, qkdResponse);
            
            // Update UI with new key
            this.displayQuantumKey(qkdResponse);
            
            return qkdResponse;
        } catch (error) {
            console.error('QKD Key Retrieval Error:', error);
            this.showError('Failed to retrieve quantum key');
            return null;
        }
    }

    // Mock key consumption (ETSI GS QKD 014 key lifecycle)
    async consumeQuantumKey(keyId) {
        try {
            const key = this.keyCache.get(keyId);
            if (!key) {
                throw new Error(`Key ${keyId} not found`);
            }

            // Simulate key consumption
            await new Promise(resolve => setTimeout(resolve, 50));
            
            key.status = "CONSUMED";
            key.consumed_at = new Date().toISOString();
            
            // Remove from cache after consumption (one-time use)
            setTimeout(() => {
                this.keyCache.delete(keyId);
                this.updateKeyDisplay();
            }, 1000);

            return { success: true, message: `Key ${keyId} consumed successfully` };
        } catch (error) {
            console.error('Key Consumption Error:', error);
            return { success: false, error: error.message };
        }
    }

    // Display quantum key in UI with animations
    displayQuantumKey(qkdData) {
        const keyContainer = document.getElementById('quantum-keys-display');
        if (!keyContainer) return;

        const keyElement = document.createElement('div');
        keyElement.className = 'glass-card p-4 mb-3 quantum-key-item animate-key-generation animate-violet-glow animate-quantum-transition';
        keyElement.innerHTML = `
            <div class="flex justify-between items-start mb-2">
                <span class="text-violet-300 font-mono text-sm quantum-flow-line">${qkdData.key_id}</span>
                <span class="security-level level-${qkdData.metadata.security_level} animate-security-pulse">
                    Level ${qkdData.metadata.security_level}
                </span>
            </div>
            <div class="text-xs text-gray-400 mb-2">
                <div>Length: ${qkdData.metadata.length} bits | Error Rate: ${(qkdData.metadata.error_rate * 100).toFixed(2)}%</div>
                <div>Protocol: ${qkdData.metadata.protocol} | Distance: ${qkdData.metadata.distance_km} km</div>
                <div>Fidelity: ${(qkdData.metadata.entanglement_fidelity * 100).toFixed(1)}%</div>
            </div>
            <div class="text-xs font-mono text-violet-200 break-all bg-black/30 p-2 rounded">
                ${qkdData.key.substring(0, 32)}...
            </div>
            <button class="consume-key-btn mt-2 px-3 py-1 bg-red-500/20 text-red-300 text-xs rounded hover:bg-red-500/30" 
                    data-key-id="${qkdData.key_id}">
                Consume Key
            </button>
        `;

        keyContainer.prepend(keyElement);
        this.updateQKDStatus();
    }

    // Update QKD connection status
    updateQKDStatus() {
        const statusElement = document.querySelector('.qkd-status');
        if (statusElement) {
            this.isConnected = true;
            statusElement.textContent = 'Connected';
            statusElement.className = 'qkd-status text-green-400';
        }

        // Update key count
        const keyCountElement = document.querySelector('.quantum-key-count');
        if (keyCountElement) {
            keyCountElement.textContent = this.keyCache.size;
        }
    }

    // Start continuous QKD simulation
    startQKDSimulation() {
        // Generate initial keys
        setTimeout(() => this.retrieveQuantumKey(), 1000);
        setTimeout(() => this.retrieveQuantumKey(), 2500);
        setTimeout(() => this.retrieveQuantumKey(), 4000);

        // Periodic key generation (every 30-60 seconds)
        setInterval(() => {
            if (this.keyCache.size < 5) { // Maintain 5 keys max
                this.retrieveQuantumKey();
            }
        }, 30000 + Math.random() * 30000);
    }

    // Initialize event listeners
    initializeEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            // Manual key generation button
            const generateBtn = document.getElementById('generate-qkd-key');
            if (generateBtn) {
                generateBtn.addEventListener('click', () => this.retrieveQuantumKey());
            }

            // Key consumption handlers
            document.addEventListener('click', (e) => {
                if (e.target.classList.contains('consume-key-btn')) {
                    const keyId = e.target.getAttribute('data-key-id');
                    this.consumeQuantumKey(keyId);
                    e.target.closest('.quantum-key-item').style.opacity = '0.5';
                    e.target.textContent = 'Consuming...';
                    e.target.disabled = true;
                }
            });

            // Encryption level change handler
            const encryptionSelect = document.getElementById('encryption-level');
            if (encryptionSelect) {
                encryptionSelect.addEventListener('change', (e) => {
                    this.updateEncryptionLevel(e.target.value);
                });
            }
        });
    }

    // Update encryption level based on available keys
    updateEncryptionLevel(level) {
        const encryptionInfo = {
            '1': { name: 'Quantum Secure', color: 'text-green-400', requirement: 'QKD Key Required' },
            '2': { name: 'Quantum-aided AES', color: 'text-blue-400', requirement: 'QKD + AES-256' },
            '3': { name: 'Hybrid PQC', color: 'text-yellow-400', requirement: 'Post-Quantum Crypto' },
            '4': { name: 'No Quantum Security', color: 'text-red-400', requirement: 'Classical Only' }
        };

        const info = encryptionInfo[level];
        const statusElement = document.querySelector('.encryption-status');
        if (statusElement && info) {
            statusElement.innerHTML = `
                <span class="${info.color}">${info.name}</span>
                <div class="text-xs text-gray-400">${info.requirement}</div>
            `;
        }

        // Log encryption level change
        console.log(`[QuMail] Encryption level changed to: ${info?.name || 'Unknown'}`);
    }

    // Update key display
    updateKeyDisplay() {
        const keyContainer = document.getElementById('quantum-keys-display');
        if (!keyContainer) return;

        // Remove consumed keys from display
        const keyItems = keyContainer.querySelectorAll('.quantum-key-item');
        keyItems.forEach(item => {
            const keyId = item.querySelector('.consume-key-btn')?.getAttribute('data-key-id');
            if (keyId && !this.keyCache.has(keyId)) {
                item.remove();
            }
        });

        // Update the key counter after removing keys
        this.updateQKDStatus();
    }

    // Show error message
    showError(message) {
        console.error(`[QuMail QKD Error] ${message}`);
        // Could add toast notification here
    }
}

// Initialize Quantum Key Manager
const qkdManager = new QuantumKeyManager();

// Expose qkdManager globally for testing
window.qkdManager = qkdManager;

// Expose to main process for IPC communication
if (window.electronAPI) {
    window.electronAPI.onQKDRequest = (callback) => {
        qkdManager.retrieveQuantumKey().then(callback);
    };
}

// Console welcome message
console.log(`
🔐 QuMail Quantum Key Distribution System Initialized
📡 ETSI GS QKD 014 Compliant Mock API Active
🚀 ISRO Quantum Network Simulation Ready
⚡ Quantum-Secure Email Client Online
`);

// Export for potential module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { QuantumKeyManager };
}
