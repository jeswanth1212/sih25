#!/usr/bin/env python3
"""
QuMail Frontend-Backend Integration Test Suite
Tests the complete integration between frontend and backend APIs
"""

import requests
import json
import time
from typing import Dict, Any

class FrontendBackendIntegrationTester:
    def __init__(self):
        self.base_url = "http://localhost:5000"
        self.test_results = []
        
    def run_all_tests(self):
        """Run all integration tests"""
        print("🚀 QuMail Frontend-Backend Integration Test Suite")
        print("=" * 60)
        
        # Test 1: API Connectivity
        self.test_api_connectivity()
        
        # Test 2: Encryption Levels Endpoint
        self.test_encryption_levels()
        
        # Test 3: All Security Levels Encryption
        self.test_all_security_levels()
        
        # Test 4: Encryption-Decryption Round Trip
        self.test_encryption_decryption_roundtrip()
        
        # Test 5: QKD Integration
        self.test_qkd_integration()
        
        # Test 6: Error Handling
        self.test_error_handling()
        
        # Print Results
        self.print_test_summary()
        
    def test_api_connectivity(self):
        """Test basic API connectivity"""
        print("\n🔍 Test 1: API Connectivity")
        print("-" * 30)
        
        try:
            response = requests.get(f"{self.base_url}/")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Backend API is running: {data.get('system', 'Unknown')}")
                self.test_results.append(("API Connectivity", "PASS", "Backend API responding"))
            else:
                print(f"❌ Backend API returned status {response.status_code}")
                self.test_results.append(("API Connectivity", "FAIL", f"Status {response.status_code}"))
        except Exception as e:
            print(f"❌ Failed to connect to backend API: {e}")
            self.test_results.append(("API Connectivity", "FAIL", str(e)))
    
    def test_encryption_levels(self):
        """Test encryption levels endpoint"""
        print("\n🔍 Test 2: Encryption Levels Endpoint")
        print("-" * 40)
        
        try:
            response = requests.get(f"{self.base_url}/api/encrypt/levels")
            if response.status_code == 200:
                data = response.json()
                
                if data.get('success'):
                    levels = data.get('encryption_levels', {})
                    print(f"✅ Encryption levels endpoint working")
                    print(f"📊 Available levels: {list(levels.keys())}")
                    
                    # Check each level
                    for level_name, level_info in levels.items():
                        print(f"   {level_name}: {level_info.get('name', 'Unknown')}")
                    
                    self.test_results.append(("Encryption Levels", "PASS", f"{len(levels)} levels available"))
                else:
                    print(f"❌ Encryption levels endpoint returned error: {data.get('error')}")
                    self.test_results.append(("Encryption Levels", "FAIL", data.get('error', 'Unknown error')))
            else:
                print(f"❌ Encryption levels endpoint returned status {response.status_code}")
                self.test_results.append(("Encryption Levels", "FAIL", f"Status {response.status_code}"))
                
        except Exception as e:
            print(f"❌ Failed to test encryption levels: {e}")
            self.test_results.append(("Encryption Levels", "FAIL", str(e)))
    
    def test_all_security_levels(self):
        """Test encryption for all security levels"""
        print("\n🔍 Test 3: All Security Levels Encryption")
        print("-" * 45)
        
        test_message = "This is a test message for QuMail encryption testing."
        
        for level in range(1, 5):
            try:
                print(f"\n   Testing Level {level}...")
                
                request_data = {
                    "plaintext": test_message,
                    "security_level": level,
                    "sender": "alice@isro.gov.in",
                    "recipient": "bob@isro.gov.in",
                    "subject": f"Test Level {level}"
                }
                
                response = requests.post(
                    f"{self.base_url}/api/encrypt",
                    json=request_data,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        metadata = data['encrypted_data']['metadata']
                        print(f"   ✅ Level {level}: {metadata['algorithm']}")
                        print(f"      🔑 Key Source: {metadata['key_source']}")
                        print(f"      🛡️ Quantum Resistant: {metadata['quantum_resistant']}")
                        print(f"      📋 ETSI Compliant: {metadata['etsi_compliant']}")
                        
                        self.test_results.append((f"Level {level} Encryption", "PASS", metadata['algorithm']))
                    else:
                        print(f"   ❌ Level {level}: {data.get('error')}")
                        self.test_results.append((f"Level {level} Encryption", "FAIL", data.get('error')))
                else:
                    print(f"   ❌ Level {level}: HTTP {response.status_code}")
                    self.test_results.append((f"Level {level} Encryption", "FAIL", f"HTTP {response.status_code}"))
                    
            except Exception as e:
                print(f"   ❌ Level {level}: {e}")
                self.test_results.append((f"Level {level} Encryption", "FAIL", str(e)))
    
    def test_encryption_decryption_roundtrip(self):
        """Test complete encryption-decryption cycle"""
        print("\n🔍 Test 4: Encryption-Decryption Round Trip")
        print("-" * 45)
        
        test_message = "Round trip test message for QuMail encryption system."
        
        for level in [1, 2, 3, 4]:  # Test all levels
            try:
                print(f"\n   Testing Level {level} round trip...")
                
                # Step 1: Encrypt
                encrypt_data = {
                    "plaintext": test_message,
                    "security_level": level,
                    "sender": "alice@isro.gov.in",
                    "recipient": "bob@isro.gov.in",
                    "subject": f"Round Trip Test Level {level}"
                }
                
                encrypt_response = requests.post(
                    f"{self.base_url}/api/encrypt",
                    json=encrypt_data,
                    headers={"Content-Type": "application/json"}
                )
                
                if encrypt_response.status_code != 200:
                    print(f"   ❌ Encryption failed: HTTP {encrypt_response.status_code}")
                    self.test_results.append((f"Level {level} Round Trip", "FAIL", "Encryption failed"))
                    continue
                
                encrypt_result = encrypt_response.json()
                if not encrypt_result.get('success'):
                    print(f"   ❌ Encryption failed: {encrypt_result.get('error')}")
                    self.test_results.append((f"Level {level} Round Trip", "FAIL", "Encryption failed"))
                    continue
                
                # Step 2: Decrypt
                decrypt_data = {
                    "encrypted_data": encrypt_result['encrypted_data']
                }
                
                decrypt_response = requests.post(
                    f"{self.base_url}/api/decrypt",
                    json=decrypt_data,
                    headers={"Content-Type": "application/json"}
                )
                
                if decrypt_response.status_code != 200:
                    print(f"   ❌ Decryption failed: HTTP {decrypt_response.status_code}")
                    self.test_results.append((f"Level {level} Round Trip", "FAIL", "Decryption failed"))
                    continue
                
                decrypt_result = decrypt_response.json()
                if not decrypt_result.get('success'):
                    print(f"   ❌ Decryption failed: {decrypt_result.get('error')}")
                    self.test_results.append((f"Level {level} Round Trip", "FAIL", "Decryption failed"))
                    continue
                
                # Step 3: Verify
                decrypted_text = decrypt_result['plaintext']
                if decrypted_text == test_message:
                    print(f"   ✅ Level {level}: Round trip successful")
                    algorithm = encrypt_result['encrypted_data']['metadata']['algorithm']
                    self.test_results.append((f"Level {level} Round Trip", "PASS", f"{algorithm} verified"))
                else:
                    print(f"   ❌ Level {level}: Message mismatch")
                    print(f"      Expected: {test_message}")
                    print(f"      Got: {decrypted_text}")
                    self.test_results.append((f"Level {level} Round Trip", "FAIL", "Message mismatch"))
                    
            except Exception as e:
                print(f"   ❌ Level {level}: {e}")
                self.test_results.append((f"Level {level} Round Trip", "FAIL", str(e)))
    
    def test_qkd_integration(self):
        """Test QKD API integration"""
        print("\n🔍 Test 5: QKD Integration")
        print("-" * 30)
        
        try:
            # Test QKD key generation
            response = requests.get(f"{self.base_url}/api/qkd/key")
            if response.status_code == 200:
                data = response.json()
                if 'key_id' in data and 'key' in data:
                    print(f"✅ QKD key generation working: {data['key_id']}")
                    self.test_results.append(("QKD Integration", "PASS", "Key generation successful"))
                else:
                    print(f"❌ QKD response missing required fields")
                    self.test_results.append(("QKD Integration", "FAIL", "Missing fields"))
            else:
                print(f"❌ QKD API returned status {response.status_code}")
                self.test_results.append(("QKD Integration", "FAIL", f"Status {response.status_code}"))
                
        except Exception as e:
            print(f"❌ QKD integration test failed: {e}")
            self.test_results.append(("QKD Integration", "FAIL", str(e)))
    
    def test_error_handling(self):
        """Test error handling"""
        print("\n🔍 Test 6: Error Handling")
        print("-" * 30)
        
        # Test invalid security level
        try:
            invalid_data = {
                "plaintext": "Test message",
                "security_level": 99,  # Invalid level
                "sender": "alice@isro.gov.in",
                "recipient": "bob@isro.gov.in"
            }
            
            response = requests.post(
                f"{self.base_url}/api/encrypt",
                json=invalid_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 400:
                data = response.json()
                if 'error' in data:
                    print("✅ Invalid security level properly rejected")
                    self.test_results.append(("Error Handling", "PASS", "Invalid level rejected"))
                else:
                    print("❌ Error response missing error field")
                    self.test_results.append(("Error Handling", "FAIL", "Missing error field"))
            else:
                print(f"❌ Expected 400 status, got {response.status_code}")
                self.test_results.append(("Error Handling", "FAIL", f"Wrong status {response.status_code}"))
                
        except Exception as e:
            print(f"❌ Error handling test failed: {e}")
            self.test_results.append(("Error Handling", "FAIL", str(e)))
    
    def print_test_summary(self):
        """Print test results summary"""
        print("\n" + "=" * 60)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 60)
        
        passed = 0
        failed = 0
        
        for test_name, result, details in self.test_results:
            status_icon = "✅" if result == "PASS" else "❌"
            print(f"{status_icon} {test_name:<30} {result:<6} {details}")
            
            if result == "PASS":
                passed += 1
            else:
                failed += 1
        
        print("-" * 60)
        print(f"📈 TOTAL: {passed + failed} tests")
        print(f"✅ PASSED: {passed}")
        print(f"❌ FAILED: {failed}")
        
        if failed == 0:
            print("\n🎉 ALL TESTS PASSED! Frontend-Backend integration is working perfectly!")
        else:
            print(f"\n⚠️ {failed} tests failed. Please check the issues above.")
        
        print("=" * 60)

if __name__ == "__main__":
    tester = FrontendBackendIntegrationTester()
    tester.run_all_tests()
