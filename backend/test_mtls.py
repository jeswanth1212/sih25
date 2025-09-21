#!/usr/bin/env python3
"""
QuMail mTLS Test Script
Tests mutual TLS authentication for ETSI GS QKD 014 API
"""

import requests
import json
import ssl
import os
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class QuMailmTLSTest:
    """Test mTLS functionality for QuMail API"""
    
    def __init__(self, base_url="https://localhost:5443", cert_dir="certs"):
        """Initialize mTLS test"""
        self.base_url = base_url
        self.cert_dir = cert_dir
        
        # Certificate paths
        self.ca_cert = os.path.join(cert_dir, "ca.crt")
        self.client_cert = os.path.join(cert_dir, "qumail-client.crt")
        self.client_key = os.path.join(cert_dir, "qumail-client.key")
        self.alice_cert = os.path.join(cert_dir, "alice.crt")
        self.alice_key = os.path.join(cert_dir, "alice.key")
        self.bob_cert = os.path.join(cert_dir, "bob.crt")
        self.bob_key = os.path.join(cert_dir, "bob.key")
        
    def test_no_client_cert(self):
        """Test connection without client certificate (should fail)"""
        print("🔒 Test 1: Connection without client certificate")
        try:
            response = requests.get(f"{self.base_url}/api/mtls/status", 
                                  verify=self.ca_cert, timeout=5)
            print("❌ FAILED: Connection should have been rejected")
            return False
        except requests.exceptions.SSLError as e:
            print("✅ PASSED: Connection properly rejected without client certificate")
            print(f"   Error: {str(e)[:100]}...")
            return True
        except Exception as e:
            print(f"❌ UNEXPECTED ERROR: {e}")
            return False
    
    def test_with_client_cert(self):
        """Test connection with valid client certificate"""
        print("\n🔑 Test 2: Connection with valid client certificate")
        try:
            response = requests.get(
                f"{self.base_url}/api/mtls/status",
                cert=(self.client_cert, self.client_key),
                verify=self.ca_cert,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ PASSED: mTLS authentication successful")
                print(f"   Client CN: {data.get('client_cn', 'N/A')}")
                print(f"   Client Serial: {data.get('client_serial', 'N/A')[:16]}...")
                print(f"   Authenticated: {data.get('client_authenticated', False)}")
                return True
            else:
                print(f"❌ FAILED: HTTP {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ FAILED: {e}")
            return False
    
    def test_mtls_info_endpoint(self):
        """Test mTLS info endpoint"""
        print("\n📋 Test 3: mTLS info endpoint")
        try:
            response = requests.get(
                f"{self.base_url}/api/mtls/info",
                cert=(self.client_cert, self.client_key),
                verify=self.ca_cert,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ PASSED: mTLS info retrieved successfully")
                print(f"   Protocol: {data.get('protocol', 'N/A')}")
                print(f"   Authentication: {data.get('authentication', 'N/A')}")
                print(f"   Security Level: {data.get('security_level', 'N/A')}")
                print(f"   Compliance: {data.get('compliance', 'N/A')}")
                return True
            else:
                print(f"❌ FAILED: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ FAILED: {e}")
            return False
    
    def test_qkd_api_with_mtls(self):
        """Test QKD API endpoints with mTLS"""
        print("\n🔬 Test 4: QKD API with mTLS authentication")
        
        # Test QKD status endpoint
        try:
            response = requests.get(
                f"{self.base_url}/api/qkd/status",
                cert=(self.client_cert, self.client_key),
                verify=self.ca_cert,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ PASSED: QKD status endpoint accessible via mTLS")
                print(f"   Status: {data.get('status', 'N/A')}")
                print(f"   Active Keys: {data.get('active_keys', 'N/A')}")
                print(f"   Algorithm: {data.get('algorithm', 'N/A')}")
                return True
            else:
                print(f"❌ FAILED: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ FAILED: {e}")
            return False
    
    def test_alice_and_bob_certs(self):
        """Test Alice and Bob client certificates"""
        print("\n👥 Test 5: Alice and Bob client certificates")
        
        clients = [
            ("Alice", self.alice_cert, self.alice_key),
            ("Bob", self.bob_cert, self.bob_key)
        ]
        
        all_passed = True
        for name, cert_path, key_path in clients:
            try:
                response = requests.get(
                    f"{self.base_url}/api/mtls/status",
                    cert=(cert_path, key_path),
                    verify=self.ca_cert,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    client_cn = data.get('client_cn', 'N/A')
                    print(f"✅ {name}: Successfully authenticated as '{client_cn}'")
                else:
                    print(f"❌ {name}: Failed with HTTP {response.status_code}")
                    all_passed = False
                    
            except Exception as e:
                print(f"❌ {name}: Failed with error: {e}")
                all_passed = False
        
        return all_passed
    
    def test_hybrid_api_with_mtls(self):
        """Test Hybrid key derivation API with mTLS"""
        print("\n🔐 Test 6: Hybrid key derivation with mTLS")
        
        try:
            # Test hybrid security endpoint
            response = requests.get(
                f"{self.base_url}/api/hybrid/security",
                cert=(self.alice_cert, self.alice_key),
                verify=self.ca_cert,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ PASSED: Hybrid security endpoint accessible via mTLS")
                print(f"   Available Components: {data.get('available_components', [])}")
                print(f"   Max Security Level: {data.get('max_security_level', 'N/A')}")
                return True
            else:
                print(f"❌ FAILED: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ FAILED: {e}")
            return False
    
    def run_all_tests(self):
        """Run all mTLS tests"""
        print("🔒 QuMail mTLS Test Suite")
        print("=" * 50)
        print("Testing mutual TLS authentication for ETSI GS QKD 014 API")
        print(f"Target: {self.base_url}")
        print()
        
        tests = [
            self.test_no_client_cert,
            self.test_with_client_cert,
            self.test_mtls_info_endpoint,
            self.test_qkd_api_with_mtls,
            self.test_alice_and_bob_certs,
            self.test_hybrid_api_with_mtls
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            if test():
                passed += 1
        
        print(f"\n📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 ALL TESTS PASSED!")
            print("✅ mTLS authentication is working correctly")
            print("✅ ETSI GS QKD 014 API is properly secured")
            print("🚀 Ready for production deployment!")
        else:
            print(f"❌ {total - passed} tests failed")
            print("🔧 Please check mTLS configuration")
        
        return passed == total

def main():
    """Run mTLS tests"""
    print("QuMail mTLS Authentication Test")
    print("ISRO Smart India Hackathon 2025")
    print()
    
    # Check if certificates exist
    cert_dir = "certs"
    required_certs = ["ca.crt", "qumail-client.crt", "qumail-client.key", "alice.crt", "alice.key", "bob.crt", "bob.key"]
    
    missing_certs = []
    for cert in required_certs:
        if not os.path.exists(os.path.join(cert_dir, cert)):
            missing_certs.append(cert)
    
    if missing_certs:
        print(f"❌ Missing certificates: {', '.join(missing_certs)}")
        print("Please run: python generate_certificates.py")
        return False
    
    print("✅ All certificates found")
    print("🔍 Starting mTLS tests...")
    print()
    
    # Run tests
    tester = QuMailmTLSTest()
    success = tester.run_all_tests()
    
    if success:
        print("\n🛰️ QuMail mTLS System: OPERATIONAL")
        print("🇮🇳 JAI HIND!")
    else:
        print("\n🔧 mTLS System: NEEDS ATTENTION")
    
    return success

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
