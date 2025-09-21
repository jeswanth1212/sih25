# QuMail - Quantum Secure Email Client Backend
# Task 20: Flask App with ETSI GS QKD 014 Compliant Key Manager
# ISRO Smart India Hackathon 2025

from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
import firebase_admin
from firebase_admin import credentials, db
import json
import os
from threading import Lock

# Configuration
from config import Config
FIREBASE_CONFIG = Config.FIREBASE_CONFIG
QKD_CONFIG = Config.QKD_CONFIG
FLASK_CONFIG = Config.FLASK_CONFIG

# Import BB84 QKD Simulator
import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'simulator'))
try:
    from qkd import create_bb84_simulator
    bb84_simulator = create_bb84_simulator()
    print("✅ BB84 QKD Simulator loaded successfully")
except ImportError as e:
    print(f"⚠️ BB84 Simulator not available: {e}")
    bb84_simulator = None
except Exception as e:
    print(f"⚠️ BB84 Simulator initialization error: {e}")
    bb84_simulator = None

app = Flask(__name__)
CORS(app)  # Enable CORS for Electron frontend

# Thread safety for key operations
key_lock = Lock()

# Initialize Firebase
try:
    # Initialize Firebase with service account if available, otherwise use config
    if not firebase_admin._apps:
        if os.path.exists('firebase-service-account.json'):
            cred = credentials.Certificate('firebase-service-account.json')
            firebase_admin.initialize_app(cred, {
                'databaseURL': FIREBASE_CONFIG['databaseURL']
            })
        else:
            # Use config approach for development
            firebase_admin.initialize_app(options={
                'databaseURL': FIREBASE_CONFIG['databaseURL']
            })
    
    firebase_ref = db.reference()
    print("✅ Firebase connected successfully")
    
except Exception as e:
    print(f"⚠️ Firebase initialization warning: {e}")
    firebase_ref = None

class QuantumKeyManager:
    """ETSI GS QKD 014 Compliant Quantum Key Manager"""
    
    def __init__(self):
        self.active_keys = {}
        self.key_history = []
        self.max_keys = 10  # Default max keys
        self.key_size_bits = QKD_CONFIG['key_length']
        
    def generate_quantum_key(self):
        """Generate a 256-bit quantum key using BB84 QKD simulation"""
        with key_lock:
            if bb84_simulator:
                # Use real BB84 QKD simulation
                try:
                    print("🔬 Generating quantum key using BB84 simulation...")
                    key_data = bb84_simulator.generate_qkd_key(target_length=self.key_size_bits)
                    
                    # Validate key security
                    validation = bb84_simulator.validate_key_security(key_data)
                    if not validation["is_secure"]:
                        print(f"⚠️ Key security validation failed: {validation['recommendations']}")
                        # Generate another key if this one is not secure
                        key_data = bb84_simulator.generate_qkd_key(target_length=self.key_size_bits)
                    
                    # Store in memory
                    self.active_keys[key_data["key_id"]] = key_data
                    
                    # Store in Firebase if available
                    if firebase_ref:
                        try:
                            firebase_ref.child('qkd_keys').child(key_data["key_id"]).set(key_data)
                            print(f"🔑 BB84 Key {key_data['key_id']} stored in Firebase")
                        except Exception as e:
                            print(f"⚠️ Firebase storage error: {e}")
                    
                    metadata = key_data["metadata"]
                    print(f"🔑 Generated BB84 QKD key: {key_data['key_id']} "
                          f"(Level {metadata['security_level']}, "
                          f"{metadata['error_rate']*100:.1f}% error, "
                          f"{metadata['fidelity']:.3f} fidelity)")
                    
                    return key_data
                    
                except Exception as e:
                    print(f"❌ BB84 simulation error: {e}")
                    # Fall back to mock generation if BB84 fails
            
            # Fallback to mock generation if BB84 not available
            print("⚠️ Falling back to mock key generation...")
            
            # Generate 256-bit key (64 hex characters)
            key_material = secrets.token_hex(32)
            
            # Generate unique key ID
            timestamp = int(time.time() * 1000)
            random_suffix = secrets.randbelow(1000)
            key_id = f"qkd_mock_{timestamp}_{random_suffix}"
            
            # Simulate realistic QKD metadata
            error_rate = round(secrets.randbelow(20) / 100.0, 3)  # 0-19% error rate
            fidelity = round(0.85 + (secrets.randbelow(150) / 1000.0), 3)  # 85-99.9% fidelity
            distance_km = secrets.randbelow(100) + 10  # 10-109 km
            
            # Ensure fidelity is valid (not NaN)
            if fidelity <= 0 or fidelity > 1:
                fidelity = 0.95
            
            # QKD quality level based on error rate and fidelity
            if error_rate < 0.05 and fidelity > 0.95:
                security_level = 1  # Excellent
            elif error_rate < 0.1 and fidelity > 0.9:
                security_level = 2  # Good  
            elif error_rate < 0.15 and fidelity > 0.85:
                security_level = 3  # Fair
            else:
                security_level = 4  # Poor
            
            # ETSI GS QKD 014 compliant key structure
            key_data = {
                "key_id": key_id,
                "key": key_material,
                "metadata": {
                    "length": self.key_size_bits,
                    "error_rate": error_rate,
                    "protocol": "BB84-Mock",
                    "security_level": security_level,
                    "fidelity": fidelity,
                    "distance_km": distance_km,
                    "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace('+00:00', 'Z'),
                    "status": "available"
                }
            }
            
            # Store in memory
            self.active_keys[key_id] = key_data
            
            # Store in Firebase if available
            if firebase_ref:
                try:
                    firebase_ref.child('qkd_keys').child(key_id).set(key_data)
                    print(f"🔑 Mock Key {key_id} stored in Firebase")
                except Exception as e:
                    print(f"⚠️ Firebase storage error: {e}")
            
            print(f"🔑 Generated Mock QKD key: {key_id} (Level {security_level}, {error_rate*100:.1f}% error)")
            return key_data
    
    def get_available_keys(self):
        """Get all available keys"""
        return list(self.active_keys.values())
    
    def consume_key(self, key_id):
        """Consume (delete) a quantum key"""
        with key_lock:
            if key_id in self.active_keys:
                key_data = self.active_keys.pop(key_id)
                
                # Mark as consumed in Firebase
                if firebase_ref:
                    try:
                        firebase_ref.child('qkd_keys').child(key_id).child('metadata').update({
                            'status': 'consumed',
                            'consumed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                        })
                        # Move to history
                        firebase_ref.child('qkd_history').child(key_id).set(key_data)
                        firebase_ref.child('qkd_keys').child(key_id).delete()
                        print(f"🔑 Key {key_id} consumed and moved to history")
                    except Exception as e:
                        print(f"⚠️ Firebase consume error: {e}")
                
                self.key_history.append(key_data)
                return True
            return False
    
    def cleanup_expired_keys(self):
        """Remove expired keys"""
        current_time = datetime.now(timezone.utc)
        expired_keys = []
        
        for key_id, key_data in self.active_keys.items():
            expires_at = datetime.fromisoformat(key_data['metadata']['expires_at'].replace('Z', '+00:00'))
            if current_time > expires_at:
                expired_keys.append(key_id)
        
        for key_id in expired_keys:
            print(f"⏰ Expiring key: {key_id}")
            self.consume_key(key_id)

# Initialize QKD Manager
qkd_manager = QuantumKeyManager()

# Generate initial keys (smaller for faster startup)
print("🔄 Generating initial QKD keys for startup...")
for i in range(3):
    print(f"  Generating key {i+1}/3...")
    if bb84_simulator:
        # Generate smaller keys for faster startup
        key_data = bb84_simulator.generate_qkd_key(target_length=64)  # 64-bit for speed
        qkd_manager.active_keys[key_data["key_id"]] = key_data
    else:
        qkd_manager.generate_quantum_key()
print("✅ Initial QKD keys generated")

@app.route('/')
def home():
    """API Information"""
    return jsonify({
        "service": "QuMail Quantum Key Manager",
        "version": "1.0.0",
        "standard": "ETSI GS QKD 014",
        "description": "ISRO Smart India Hackathon 2025 - Quantum Secure Email",
        "endpoints": {
            "get_key": "/api/qkd/key",
            "get_keys": "/api/qkd/keys", 
            "consume_key": "/api/qkd/consume/<key_id>",
            "status": "/api/qkd/status"
        }
    })

@app.route('/api/qkd/key', methods=['GET'])
def get_quantum_key():
    """
    ETSI GS QKD 014 Compliant Key Retrieval Endpoint
    Returns a single quantum key with metadata
    """
    try:
        # Clean up expired keys first
        qkd_manager.cleanup_expired_keys()
        
        # Check if we have available keys
        available_keys = qkd_manager.get_available_keys()
        
        if not available_keys:
            # Generate new key if none available
            key_data = qkd_manager.generate_quantum_key()
        else:
            # Return first available key (for automated retrieval)
            key_data = available_keys[0]
        
        # ETSI GS QKD 014 compliant response
        response = {
            "key_id": key_data["key_id"],
            "key": key_data["key"],
            "metadata": key_data["metadata"]
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"❌ Error getting key: {e}")
        return jsonify({
            "error": "Internal server error",
            "message": "Failed to get quantum key"
        }), 500

@app.route('/api/qkd/keys', methods=['GET'])
def get_all_keys():
    """Get all available quantum keys"""
    try:
        qkd_manager.cleanup_expired_keys()
        keys = qkd_manager.get_available_keys()
        
        return jsonify({
            "total_keys": len(keys),
            "keys": keys
        }), 200
        
    except Exception as e:
        print(f"❌ Error fetching keys: {e}")
        return jsonify({"error": "Failed to fetch keys"}), 500

@app.route('/api/qkd/consume/<key_id>', methods=['POST', 'DELETE'])
def consume_quantum_key(key_id):
    """Consume (delete) a quantum key"""
    try:
        success = qkd_manager.consume_key(key_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": f"Key {key_id} consumed successfully",
                "key_id": key_id
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": "Key not found",
                "key_id": key_id
            }), 404
            
    except Exception as e:
        print(f"❌ Error consuming key: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to consume key"
        }), 500

@app.route('/api/qkd/generate', methods=['POST'])
def generate_new_key():
    """Generate a new quantum key"""
    try:
        # Check if we're at max capacity
        if len(qkd_manager.active_keys) >= qkd_manager.max_keys:
            return jsonify({
                "error": "Maximum key capacity reached",
                "max_keys": qkd_manager.max_keys,
                "current_keys": len(qkd_manager.active_keys)
            }), 429
        
        key_data = qkd_manager.generate_quantum_key()
        
        return jsonify({
            "success": True,
            "message": "New quantum key generated",
            "key_data": key_data
        }), 201
        
    except Exception as e:
        print(f"❌ Error generating new key: {e}")
        return jsonify({"error": "Failed to generate key"}), 500

@app.route('/api/qkd/status', methods=['GET'])
def qkd_status():
    """Get QKD system status"""
    try:
        qkd_manager.cleanup_expired_keys()
        
        status = {
            "system": "QuMail QKD Manager",
            "status": "operational",
            "active_keys": len(qkd_manager.active_keys),
            "max_keys": qkd_manager.max_keys,
            "total_generated": len(qkd_manager.key_history) + len(qkd_manager.active_keys),
            "firebase_connected": firebase_ref is not None,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
        return jsonify(status), 200
        
    except Exception as e:
        print(f"❌ Error getting status: {e}")
        return jsonify({"error": "Failed to get status"}), 500

@app.route('/api/qkd/bb84/test', methods=['GET'])
def test_bb84_simulator():
    """Test the BB84 QKD simulator directly"""
    try:
        if not bb84_simulator:
            return jsonify({
                "error": "BB84 simulator not available",
                "message": "Qiskit BB84 simulator is not loaded"
            }), 503
        
        # Generate a test key
        test_key = bb84_simulator.generate_qkd_key(target_length=64)  # Smaller test key
        validation = bb84_simulator.validate_key_security(test_key)
        
        return jsonify({
            "simulator_status": "operational",
            "test_key_generated": True,
            "key_preview": {
                "key_id": test_key["key_id"],
                "protocol": test_key["metadata"]["protocol"],
                "error_rate": test_key["metadata"]["error_rate"],
                "fidelity": test_key["metadata"]["fidelity"],
                "security_level": test_key["metadata"]["security_level"],
                "quantum_parameters": test_key["metadata"].get("quantum_parameters", {})
            },
            "security_validation": validation,
            "message": "BB84 QKD simulator is working correctly"
        }), 200
        
    except Exception as e:
        print(f"❌ Error testing BB84 simulator: {e}")
        return jsonify({
            "error": "BB84 simulator test failed",
            "message": str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    print("🚀 Starting QuMail QKD Manager...")
    print(f"📡 ETSI GS QKD 014 Compliant API")
    print(f"🔑 Key size: {QKD_CONFIG['key_length']} bits")
    print(f"📊 Max keys: 10")
    print(f"🌐 Server: http://localhost:{FLASK_CONFIG['port']}")
    
    app.run(
        host=FLASK_CONFIG['host'],
        port=FLASK_CONFIG['port'],
        debug=FLASK_CONFIG['debug']
    )
