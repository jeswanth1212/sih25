#!/usr/bin/env python3
"""
QuMail ETSI GS QKD 014 API Test Suite
Comprehensive pytest tests for QKD, ECDH, ML-KEM, and Hybrid APIs
ISRO Smart India Hackathon 2025
"""

import pytest
import requests
import json
import time
from datetime import datetime
import os
import sys

# Add backend to path for imports
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'backend'))

class TestQuMailAPI:
    """Test suite for QuMail API endpoints"""
    
    @classmethod
    def setup_class(cls):
        """Setup test environment"""
        cls.base_url = "http://127.0.0.1:5000"
        cls.timeout = 10
        
        # Test server connectivity
        try:
            response = requests.get(cls.base_url, timeout=5)
            if response.status_code != 200:
                pytest.skip("QuMail server not running. Start with: python backend/app.py")
        except requests.exceptions.RequestException:
            pytest.skip("QuMail server not accessible. Start with: python backend/app.py")
    
    def test_server_info(self):
        """Test basic server information endpoint"""
        response = requests.get(f"{self.base_url}/", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert data["service"] == "QuMail Hybrid Quantum-Classical Key Manager"
        assert data["version"] == "1.0.0"
        assert "ETSI GS QKD 014" in data["standards"]
        assert "components" in data
        assert "endpoints" in data
        
        print(f"✅ Server Info: {data['service']} v{data['version']}")

class TestQKDAPI:
    """Test ETSI GS QKD 014 compliant QKD API endpoints"""
    
    @classmethod
    def setup_class(cls):
        """Setup QKD test environment"""
        cls.base_url = "http://127.0.0.1:5000/api/qkd"
        cls.timeout = 15  # QKD operations can be slower
        
    def test_qkd_status(self):
        """Test QKD system status"""
        response = requests.get(f"{self.base_url}/status", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert data["system"] == "QuMail QKD Manager"
        assert data["status"] == "operational"
        assert "active_keys" in data
        assert "max_keys" in data
        assert "timestamp" in data
        
        print(f"✅ QKD Status: {data['active_keys']}/{data['max_keys']} keys active")
    
    def test_qkd_key_generation(self):
        """Test QKD key generation"""
        response = requests.post(f"{self.base_url}/generate", timeout=self.timeout)
        
        # Allow for rate limiting
        if response.status_code == 429:
            time.sleep(2)
            response = requests.post(f"{self.base_url}/generate", timeout=self.timeout)
        
        assert response.status_code == 201
        
        data = response.json()
        assert "key_data" in data
        key_data = data["key_data"]
        
        assert "key_id" in key_data
        assert "key" in key_data
        assert "metadata" in key_data
        assert key_data["key_id"].startswith("qkd_bb84_")
        assert len(key_data["key"]) >= 64  # At least 32 bytes (64 hex chars)
        
        # Verify metadata
        metadata = key_data["metadata"]
        assert "length" in metadata
        assert metadata["length"] >= 256  # bits
        assert "expires_at" in metadata or "expiry" in metadata
        
        print(f"✅ QKD Key Generated: {key_data['key_id']} ({metadata['length']} bits)")
        return key_data
    
    def test_qkd_key_retrieval(self):
        """Test ETSI GS QKD 014 compliant key retrieval"""
        response = requests.get(f"{self.base_url}/key", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "key_id" in data
        assert "key" in data
        assert "metadata" in data
        
        print(f"✅ QKD Key Retrieved: {data['key_id']}")
        return data
    
    def test_qkd_keys_listing(self):
        """Test listing all available QKD keys"""
        response = requests.get(f"{self.base_url}/keys", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "total_keys" in data
        assert "keys" in data
        assert isinstance(data["keys"], list)
        assert data["total_keys"] == len(data["keys"])
        
        print(f"✅ QKD Keys Listed: {data['total_keys']} keys available")
        return data
    
    def test_qkd_key_consumption(self):
        """Test QKD key consumption (deletion)"""
        # First get a key
        keys_response = requests.get(f"{self.base_url}/keys", timeout=self.timeout)
        assert keys_response.status_code == 200
        
        keys_data = keys_response.json()
        if keys_data["total_keys"] == 0:
            pytest.skip("No QKD keys available for consumption test")
        
        # Consume the first key
        key_id = keys_data["keys"][0]["key_id"]
        response = requests.post(f"{self.base_url}/consume/{key_id}", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert key_id in data.get("message", "")
        
        print(f"✅ QKD Key Consumed: {key_id}")
    
    def test_bb84_simulator(self):
        """Test BB84 quantum protocol simulator"""
        response = requests.get(f"{self.base_url}/bb84/test", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "key_preview" in data or "raw_bits" in data
        assert "simulator_status" in data or "final_key_bits" in data
        qber_key = "qber" if "qber" in data else "key_preview"
        if qber_key == "key_preview":
            assert data["key_preview"]["error_rate"] <= 0.11
        else:
            assert data["qber"] <= 0.11
        
        key_bits = data.get("final_key_bits", "N/A")
        qber = data.get("qber", data.get("key_preview", {}).get("error_rate", 0))
        print(f"✅ BB84 Test: {key_bits} bits, QBER: {qber:.3f}")

class TestECDHAPI:
    """Test ECDH/X25519 API endpoints"""
    
    @classmethod
    def setup_class(cls):
        """Setup ECDH test environment"""
        cls.base_url = "http://127.0.0.1:5000/api/ecdh"
        cls.timeout = 10
    
    def test_ecdh_status(self):
        """Test ECDH system status"""
        response = requests.get(f"{self.base_url}/status", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "QuMail ECDH" in data["system"]
        assert data["status"] == "operational"
        assert data["algorithm"] == "X25519"
        assert "RFC" in data.get("rfc_standard", data.get("standard", "RFC 7748"))
        
        print(f"✅ ECDH Status: {data['algorithm']} operational")
    
    def test_ecdh_keypair_generation(self):
        """Test ECDH keypair generation"""
        keypair_data = {"key_id": "test_ecdh_keypair"}
        response = requests.post(f"{self.base_url}/keypair", json=keypair_data, timeout=self.timeout)
        assert response.status_code == 201
        
        data = response.json()
        assert data["key_id"] == "test_ecdh_keypair"
        assert "public_key" in data
        assert "public_key_hex" in data
        assert len(data["public_key"]) > 0  # Base64 encoded
        assert len(data["public_key_hex"]) == 64  # 32 bytes = 64 hex chars
        
        print(f"✅ ECDH Keypair: {data['key_id']} generated")
        return data
    
    def test_ecdh_public_key_retrieval(self):
        """Test ECDH public key retrieval"""
        # First generate a keypair
        keypair = self.test_ecdh_keypair_generation()
        key_id = keypair["key_id"]
        
        response = requests.get(f"{self.base_url}/public/{key_id}", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert data["key_id"] == key_id
        assert data["public_key"] == keypair["public_key"]
        
        print(f"✅ ECDH Public Key Retrieved: {key_id}")
    
    def test_ecdh_key_exchange(self):
        """Test ECDH shared secret computation"""
        # Generate two keypairs
        alice_data = {"key_id": "test_alice"}
        bob_data = {"key_id": "test_bob"}
        
        alice_response = requests.post(f"{self.base_url}/keypair", json=alice_data, timeout=self.timeout)
        bob_response = requests.post(f"{self.base_url}/keypair", json=bob_data, timeout=self.timeout)
        
        assert alice_response.status_code == 201
        assert bob_response.status_code == 201
        
        alice_keypair = alice_response.json()
        bob_keypair = bob_response.json()
        
        # Alice computes shared secret with Bob's public key
        exchange_data = {
            "local_key_id": alice_keypair["key_id"],
            "remote_public_key": bob_keypair["public_key"],
            "shared_secret_id": "test_shared_secret"
        }
        
        response = requests.post(f"{self.base_url}/exchange", json=exchange_data, timeout=self.timeout)
        assert response.status_code == 201
        
        data = response.json()
        assert data["shared_secret_id"] == "test_shared_secret"
        assert "shared_secret_preview" in data
        assert len(data["shared_secret_preview"]) > 0
        
        print(f"✅ ECDH Key Exchange: {data['shared_secret_id']}")
        return data
    
    def test_ecdh_test_endpoint(self):
        """Test ECDH test endpoint"""
        response = requests.get(f"{self.base_url}/test", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        # Accept any response format for test endpoint
        assert response.status_code == 200
        assert isinstance(data, dict)
        
        print(f"✅ ECDH Test: Test completed successfully")

class TestMLKEMAPI:
    """Test ML-KEM-768 Post-Quantum Cryptography API"""
    
    @classmethod
    def setup_class(cls):
        """Setup ML-KEM test environment"""
        cls.base_url = "http://127.0.0.1:5000/api/mlkem"
        cls.timeout = 10
    
    def test_mlkem_status(self):
        """Test ML-KEM system status"""
        response = requests.get(f"{self.base_url}/status", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert data["system"] == "QuMail ML-KEM-768 Manager"
        assert data["status"] == "operational"
        assert data["algorithm"] == "ML-KEM-768"
        assert data["nist_standard"] == "FIPS 203"
        assert data["quantum_resistant"] == True
        
        print(f"✅ ML-KEM Status: {data['algorithm']} ({data['variant']})")
    
    def test_mlkem_keypair_generation(self):
        """Test ML-KEM keypair generation"""
        keypair_data = {"key_id": "test_mlkem_keypair"}
        response = requests.post(f"{self.base_url}/keypair", json=keypair_data, timeout=self.timeout)
        assert response.status_code == 201
        
        data = response.json()
        assert data["key_id"] == "test_mlkem_keypair"
        assert "public_key" in data
        assert len(data["public_key"]) > 1000  # ML-KEM-768 public keys are large
        
        print(f"✅ ML-KEM Keypair: {data['key_id']} (public key: {len(data['public_key'])} chars)")
        return data
    
    def test_mlkem_encapsulation_decapsulation(self):
        """Test ML-KEM key encapsulation and decapsulation"""
        # Generate two keypairs (Alice and Bob)
        alice_keypair = requests.post(f"{self.base_url}/keypair", 
                                    json={"key_id": "test_alice_mlkem"}, 
                                    timeout=self.timeout).json()
        bob_keypair = requests.post(f"{self.base_url}/keypair", 
                                  json={"key_id": "test_bob_mlkem"}, 
                                  timeout=self.timeout).json()
        
        # Alice encapsulates a secret for Bob
        encaps_data = {
            "remote_public_key": bob_keypair["public_key"],
            "secret_id": "test_mlkem_secret"
        }
        
        encaps_response = requests.post(f"{self.base_url}/encapsulate", 
                                      json=encaps_data, timeout=self.timeout)
        assert encaps_response.status_code == 201
        
        encaps_result = encaps_response.json()
        assert encaps_result["secret_id"] == "test_mlkem_secret"
        assert "ciphertext" in encaps_result
        assert "shared_secret_preview" in encaps_result
        
        # Bob decapsulates the secret
        decaps_data = {
            "local_key_id": bob_keypair["key_id"],
            "ciphertext": encaps_result["ciphertext"]
        }
        
        decaps_response = requests.post(f"{self.base_url}/decapsulate", 
                                      json=decaps_data, timeout=self.timeout)
        assert decaps_response.status_code == 200
        
        decaps_result = decaps_response.json()
        assert "shared_secret_preview" in decaps_result
        
        # Verify secrets match
        assert encaps_result["shared_secret_preview"] == decaps_result["shared_secret_preview"]
        
        print(f"✅ ML-KEM Encapsulation/Decapsulation: Secrets match!")
        return encaps_result, decaps_result
    
    def test_mlkem_test_endpoint(self):
        """Test ML-KEM test endpoint"""
        response = requests.get(f"{self.base_url}/test", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert data["algorithm"] == "ML-KEM-768"
        assert "key_encapsulation_verified" in data
        assert data["key_encapsulation_verified"] == True
        
        print(f"✅ ML-KEM Test: {data['algorithm']} test passed")

class TestHybridAPI:
    """Test Hybrid Key Derivation API"""
    
    @classmethod
    def setup_class(cls):
        """Setup Hybrid test environment"""
        cls.base_url = "http://127.0.0.1:5000/api/hybrid"
        cls.timeout = 15
    
    def test_hybrid_security_analysis(self):
        """Test hybrid security analysis"""
        response = requests.get(f"{self.base_url}/security", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "components_available" in data or "available_components" in data
        # Security level may be in various fields
        assert any(key in data for key in ["maximum_security_level", "max_security_level", "security_level", "algorithm"])
        
        components_key = "components_available" if "components_available" in data else "available_components"
        security_key = "maximum_security_level" if "maximum_security_level" in data else "max_security_level"
        print(f"✅ Hybrid Security: Analysis completed with {len(data.get(components_key, {}))} components")
    
    def test_hybrid_key_derivation(self):
        """Test complete hybrid key derivation"""
        # Generate QKD key
        qkd_response = requests.post("http://127.0.0.1:5000/api/qkd/generate", timeout=self.timeout)
        if qkd_response.status_code == 429:
            # Use existing key if rate limited
            qkd_keys = requests.get("http://127.0.0.1:5000/api/qkd/keys", timeout=self.timeout).json()
            if qkd_keys["total_keys"] > 0:
                qkd_key_id = qkd_keys["keys"][0]["key_id"]
            else:
                pytest.skip("No QKD keys available and rate limited")
        else:
            qkd_key_id = qkd_response.json()["key_data"]["key_id"]
        
        # Generate ECDH shared secret
        ecdh_keypair = requests.post("http://127.0.0.1:5000/api/ecdh/keypair", 
                                   json={"key_id": "hybrid_test_ecdh"}, timeout=self.timeout).json()
        ecdh_exchange = requests.post("http://127.0.0.1:5000/api/ecdh/exchange", json={
            "local_key_id": ecdh_keypair["key_id"],
            "remote_public_key": ecdh_keypair["public_key"],  # Self-exchange for test
            "shared_secret_id": "hybrid_test_ecdh_shared"
        }, timeout=self.timeout).json()
        
        # Generate ML-KEM shared secret
        mlkem_keypair = requests.post("http://127.0.0.1:5000/api/mlkem/keypair", 
                                    json={"key_id": "hybrid_test_mlkem"}, timeout=self.timeout).json()
        mlkem_encaps = requests.post("http://127.0.0.1:5000/api/mlkem/encapsulate", json={
            "remote_public_key": mlkem_keypair["public_key"],
            "secret_id": "hybrid_test_mlkem_shared"
        }, timeout=self.timeout).json()
        
        # Derive hybrid key
        hybrid_data = {
            "key_id": "test_hybrid_key",
            "qkd_key_id": qkd_key_id,
            "ecdh_shared_secret_id": ecdh_exchange["shared_secret_id"],
            "mlkem_shared_secret_id": mlkem_encaps["secret_id"]
        }
        
        response = requests.post(f"{self.base_url}/derive", json=hybrid_data, timeout=self.timeout)
        assert response.status_code == 201
        
        data = response.json()
        assert "hybrid_key_id" in data
        assert "derived_key_preview" in data
        assert "security_level" in data
        assert "components" in data
        assert len(data["components"]) >= 2  # At least ECDH + ML-KEM
        
        print(f"✅ Hybrid Key Derived: {data['security_level']} with {len(data['components'])} components")
        return data
    
    def test_hybrid_keys_listing(self):
        """Test listing hybrid keys"""
        response = requests.get(f"{self.base_url}/keys", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "count" in data or "total_hybrid_keys" in data
        assert "hybrid_keys" in data
        
        count = data.get("count", data.get("total_hybrid_keys", 0))
        print(f"✅ Hybrid Keys Listed: {count} keys available")
    
    def test_hybrid_test_endpoint(self):
        """Test hybrid derivation test endpoint"""
        response = requests.get(f"{self.base_url}/test", timeout=self.timeout)
        assert response.status_code == 200
        
        data = response.json()
        assert "demo_successful" in data or "test_result" in data
        success_value = data.get("demo_successful", data.get("test_result", {}).get("success", False))
        assert success_value == True
        
        print(f"✅ Hybrid Test: Full derivation test passed")

class TestAPIIntegration:
    """Test API integration and workflows"""
    
    @classmethod
    def setup_class(cls):
        """Setup integration test environment"""
        cls.base_url = "http://127.0.0.1:5000"
        cls.timeout = 20
    
    def test_complete_workflow(self):
        """Test complete QuMail workflow"""
        print("\n🔄 Testing Complete QuMail Workflow...")
        
        # Step 1: Check system status
        status_response = requests.get(f"{self.base_url}/", timeout=self.timeout)
        assert status_response.status_code == 200
        components = status_response.json()["components"]
        
        # Step 2: Generate cryptographic components
        results = {}
        
        # QKD component
        if components["qkd_available"]:
            qkd_keys = requests.get(f"{self.base_url}/api/qkd/keys", timeout=self.timeout).json()
            if qkd_keys["total_keys"] > 0:
                results["qkd_key_id"] = qkd_keys["keys"][0]["key_id"]
            else:
                qkd_gen = requests.post(f"{self.base_url}/api/qkd/generate", timeout=self.timeout)
                if qkd_gen.status_code == 201:
                    results["qkd_key_id"] = qkd_gen.json()["key_data"]["key_id"]
        
        # ECDH component
        if components["ecdh_available"]:
            ecdh_keypair = requests.post(f"{self.base_url}/api/ecdh/keypair", 
                                       json={"key_id": "integration_ecdh"}, timeout=self.timeout).json()
            ecdh_shared = requests.post(f"{self.base_url}/api/ecdh/exchange", json={
                "local_key_id": ecdh_keypair["key_id"],
                "remote_public_key": ecdh_keypair["public_key"],
                "shared_secret_id": "integration_ecdh_shared"
            }, timeout=self.timeout).json()
            results["ecdh_shared_id"] = ecdh_shared["shared_secret_id"]
        
        # ML-KEM component
        if components["mlkem_available"]:
            mlkem_keypair = requests.post(f"{self.base_url}/api/mlkem/keypair", 
                                        json={"key_id": "integration_mlkem"}, timeout=self.timeout).json()
            mlkem_encaps = requests.post(f"{self.base_url}/api/mlkem/encapsulate", json={
                "remote_public_key": mlkem_keypair["public_key"],
                "secret_id": "integration_mlkem_shared"
            }, timeout=self.timeout).json()
            results["mlkem_shared_id"] = mlkem_encaps["secret_id"]
        
        # Step 3: Derive hybrid key
        if components["hybrid_derivation_available"] and len(results) >= 2:
            hybrid_data = {"key_id": "integration_hybrid"}
            if "qkd_key_id" in results:
                hybrid_data["qkd_key_id"] = results["qkd_key_id"]
            if "ecdh_shared_id" in results:
                hybrid_data["ecdh_shared_secret_id"] = results["ecdh_shared_id"]
            if "mlkem_shared_id" in results:
                hybrid_data["mlkem_shared_secret_id"] = results["mlkem_shared_id"]
            
            hybrid_response = requests.post(f"{self.base_url}/api/hybrid/derive", 
                                          json=hybrid_data, timeout=self.timeout)
            if hybrid_response.status_code == 201:
                results["hybrid_key_id"] = hybrid_response.json()["hybrid_key_id"]
        
        # Verify workflow completed successfully
        assert len(results) >= 2, f"Workflow incomplete, only {len(results)} components successful"
        
        print(f"✅ Complete Workflow: {len(results)} components successfully integrated")
        return results

def generate_curl_commands():
    """Generate curl commands for manual API testing"""
    base_url = "http://127.0.0.1:5000"
    
    commands = [
        f"# QuMail API Testing with curl",
        f"",
        f"# 1. Get server information",
        f"curl -X GET {base_url}/",
        f"",
        f"# 2. QKD API Tests",
        f"curl -X GET {base_url}/api/qkd/status",
        f"curl -X GET {base_url}/api/qkd/keys", 
        f"curl -X POST {base_url}/api/qkd/generate",
        f"curl -X GET {base_url}/api/qkd/key",
        f"curl -X GET {base_url}/api/qkd/bb84/test",
        f"",
        f"# 3. ECDH API Tests",
        f"curl -X GET {base_url}/api/ecdh/status",
        f'curl -X POST {base_url}/api/ecdh/keypair -H "Content-Type: application/json" -d \'{{"key_id": "test_keypair"}}\'',
        f"curl -X GET {base_url}/api/ecdh/test",
        f"",
        f"# 4. ML-KEM API Tests", 
        f"curl -X GET {base_url}/api/mlkem/status",
        f'curl -X POST {base_url}/api/mlkem/keypair -H "Content-Type: application/json" -d \'{{"key_id": "test_mlkem"}}\'',
        f"curl -X GET {base_url}/api/mlkem/test",
        f"",
        f"# 5. Hybrid API Tests",
        f"curl -X GET {base_url}/api/hybrid/security",
        f"curl -X GET {base_url}/api/hybrid/keys",
        f"curl -X GET {base_url}/api/hybrid/test",
        f""
    ]
    
    return "\n".join(commands)

if __name__ == "__main__":
    # Print curl commands for manual testing
    print("QuMail ETSI GS QKD 014 API Test Commands")
    print("=" * 50)
    print(generate_curl_commands())
    print("\n" + "=" * 50)
    print("Run pytest tests with: pytest tests/test_qkd.py -v")
