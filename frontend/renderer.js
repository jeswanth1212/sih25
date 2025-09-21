// QuMail Quantum Key Distribution Mock API - ETSI GS QKD 014 Compliant
// Renderer Process for Electron App

class QuantumKeyManager {
    constructor() {
        this.apiBaseUrl = 'http://localhost:5000/api/qkd'; // Flask QKD API endpoint
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

    // Real ETSI GS QKD 014 compliant key retrieval from Flask API
    async retrieveQuantumKey(keyId = null) {
        try {
            console.log('🔄 Requesting quantum key from Flask QKD system...');
            
            // Call Flask API
            const response = await fetch(`${this.apiBaseUrl}/key`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const qkdResponse = await response.json();
            console.log('📦 Received key data from Flask:', qkdResponse);
            
            // Cache the key
            this.keyCache.set(qkdResponse.key_id, qkdResponse);
            
            // Update UI with new key
            this.displayQuantumKey(qkdResponse);
            
            console.log(`✅ Quantum key retrieved from Flask API: ${qkdResponse.key_id}`);
            this.isConnected = true;
            
            return qkdResponse;
            
        } catch (error) {
            console.error('❌ Failed to retrieve quantum key from Flask API:', error);
            console.log('⚠️ Falling back to mock key generation...');
            this.isConnected = false;
            
            // Fallback to mock generation if API fails
            const qkdResponse = {
                key_id: keyId || `qkd_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
                key: this.generateQuantumKey(),
                metadata: this.generateQKDMetadata(),
                status: "READY",
                timestamp: new Date().toISOString(),
                qkd_node_id: "ISRO_QKD_NODE_001",
                peer_node_id: "RECIPIENT_NODE_" + Math.floor(Math.random() * 100),
            };

            this.keyCache.set(qkdResponse.key_id, qkdResponse);
            this.displayQuantumKey(qkdResponse);
            
            return qkdResponse;
        }
    }

    // Generate a NEW quantum key via Flask API (for manual generation)
    async generateNewQuantumKey() {
        try {
            console.log('🔄 Generating NEW quantum key via Flask API...');
            
            // Call Flask API to generate new key
            const response = await fetch(`${this.apiBaseUrl}/generate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            console.log('📦 New key generated via Flask:', result);
            
            if (result.success && result.key_data) {
                const qkdResponse = result.key_data;
                
                // Cache the key
                this.keyCache.set(qkdResponse.key_id, qkdResponse);
                
                // Update UI with new key
                this.displayQuantumKey(qkdResponse);
                
                console.log(`✅ NEW quantum key generated via Flask API: ${qkdResponse.key_id}`);
                this.isConnected = true;
                
                return qkdResponse;
            } else {
                throw new Error('Key generation failed');
            }
            
        } catch (error) {
            console.error('❌ Failed to generate new key via Flask API:', error);
            console.log('⚠️ Falling back to mock key generation...');
            this.isConnected = false;
            
            // Fallback to mock generation if API fails
            const qkdResponse = {
                key_id: `qkd_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
                key: this.generateQuantumKey(),
                metadata: this.generateQKDMetadata(),
                status: "READY",
                timestamp: new Date().toISOString(),
                qkd_node_id: "ISRO_QKD_NODE_001",
                peer_node_id: "RECIPIENT_NODE_" + Math.floor(Math.random() * 100),
            };

            this.keyCache.set(qkdResponse.key_id, qkdResponse);
            this.displayQuantumKey(qkdResponse);
            
            return qkdResponse;
        }
    }

    // Real key consumption via Flask API (ETSI GS QKD 014 key lifecycle)
    async consumeQuantumKey(keyId) {
        try {
            const key = this.keyCache.get(keyId);
            if (!key) {
                throw new Error(`Key ${keyId} not found`);
            }

            console.log(`🔄 Consuming key ${keyId} via Flask API...`);
            
            try {
                // Call Flask API to consume key
                const response = await fetch(`${this.apiBaseUrl}/consume/${keyId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const result = await response.json();
                console.log('📦 Key consumption result from Flask:', result);
                
                // Remove from local cache immediately
                this.keyCache.delete(keyId);
                this.updateKeyDisplay();
                
                console.log(`✅ Key consumed via Flask API: ${keyId}`);
                return result;
                
            } catch (apiError) {
                console.error('❌ Flask API consumption failed:', apiError);
                console.log('⚠️ Falling back to local consumption...');
                
                // Fallback to local consumption
                key.status = "CONSUMED";
                key.consumed_at = new Date().toISOString();
                
                setTimeout(() => {
                    this.keyCache.delete(keyId);
                    this.updateKeyDisplay();
                }, 1000);
                
                return { success: true, message: `Key ${keyId} consumed locally (API fallback)` };
            }
            
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
                generateBtn.addEventListener('click', () => this.generateNewQuantumKey());
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
                    this.updateSecurityGauge(e.target.value);
                });
                
                // Initialize security gauge with current level
                this.updateSecurityGauge(encryptionSelect.value);
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

    // Update security gauge based on encryption level
    updateSecurityGauge(level) {
        const securityBar = document.getElementById('security-bar');
        const securityIndicator = document.getElementById('security-indicator');
        const securityText = document.getElementById('security-text');
        const securityDetails = document.getElementById('security-details');
        const bitStrength = document.getElementById('bit-strength');

        if (!securityBar || !securityIndicator || !securityText || !securityDetails) {
            console.log('⚠️ Security gauge elements not found');
            return;
        }

        const securityLevels = {
            '1': {
                width: '95%',
                color: 'from-green-400 to-green-500',
                indicatorColor: 'bg-green-400',
                textColor: 'text-green-300',
                name: 'Level 1: Quantum Secure',
                description: 'QKD Only',
                bitStrength: '256-bit'
            },
            '2': {
                width: '85%',
                color: 'from-blue-400 to-blue-500',
                indicatorColor: 'bg-blue-400',
                textColor: 'text-blue-300',
                name: 'Level 2: Quantum-aided AES',
                description: 'QKD + AES-256',
                bitStrength: '192-bit'
            },
            '3': {
                width: '75%',
                color: 'from-purple-400 to-purple-500',
                indicatorColor: 'bg-purple-400',
                textColor: 'text-purple-300',
                name: 'Level 3: Hybrid PQC',
                description: 'ML-KEM + ECDH',
                bitStrength: '192-bit'
            },
            '4': {
                width: '45%',
                color: 'from-red-400 to-red-500',
                indicatorColor: 'bg-red-400',
                textColor: 'text-red-300',
                name: 'Level 4: No Quantum Security',
                description: 'Classical Only',
                bitStrength: '128-bit'
            }
        };

        const config = securityLevels[level] || securityLevels['2'];

        // Update gauge bar with animation
        securityBar.style.width = config.width;
        securityBar.className = `h-3 rounded-full transition-all duration-700 ease-out bg-gradient-to-r ${config.color}`;

        // Update indicator dot
        securityIndicator.className = `w-2 h-2 rounded-full ${config.indicatorColor} animate-pulse`;

        // Update security level text
        securityText.className = `${config.textColor} text-sm font-medium`;
        securityText.textContent = config.name;

        // Update security details
        securityDetails.textContent = config.description;

        // Update bit strength display
        if (bitStrength) {
            bitStrength.textContent = config.bitStrength;
        }

        console.log(`🔒 Security gauge updated to Level ${level}: ${config.name} (${config.bitStrength})`);
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
