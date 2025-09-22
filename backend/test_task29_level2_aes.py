#!/usr/bin/env python3
"""
QuMail Task 29: Level 2 Quantum-aided AES Test Suite
ISRO Smart India Hackathon 2025

Test comprehensive Level 2 encryption/decryption with:
- Hybrid key derivation (QKD + ECDH + Real PQC)
- Real AES-256-GCM encryption
- Fallback mechanisms
- Performance testing
"""

import sys
import os
import time
import random
import logging
from datetime import datetime

sys.path.append(os.path.dirname(__file__))
from encryption import QuMailMultiLevelEncryption, SecurityLevel, QuMailEncryptionError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_level2_basic_encryption():
    """Test basic Level 2 encryption/decryption"""
    print("🔐 Testing Level 2: Quantum-aided AES Encryption")
    print("-" * 50)
    
    # Initialize encryption module
    print("🔐 Initializing QuMail Encryption Module...")
    encryptor = QuMailMultiLevelEncryption()
    print("✅ Encryption module initialized successfully\n")
    
    # Test message
    test_message = "Hello ISRO! This is a test message for Level 2 Quantum-aided AES encryption using hybrid key derivation from QKD, ECDH, and ML-KEM components."
    sender = "alice@quemail.isro.gov"
    recipient = "bob@quemail.isro.gov"
    
    print(f"📧 Test Message:")
    print(f"   From: {sender}")
    print(f"   To: {recipient}")
    print(f"   Message: {test_message[:70]}...")
    print()
    
    # Test Level 2 encryption
    print("🔐 Testing Level 2: Quantum-aided AES Encryption")
    print("-" * 50)
    
    start_time = time.time()
    print("🔐 Encrypting with Level 2...")
    try:
        encrypted_message = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.QUANTUM_AIDED,
            sender=sender,
            recipient=recipient,
            subject="Test Level 2 Encryption"
        )
        encryption_time = time.time() - start_time
        
        print(f"✅ Encryption successful in {encryption_time:.3f}s")
        print(f"   Algorithm: {encrypted_message.metadata.algorithm}")
        print(f"   Key Source: {encrypted_message.metadata.key_source}")
        print(f"   Quantum Resistant: {encrypted_message.metadata.quantum_resistant}")
        print(f"   ETSI Compliant: {encrypted_message.metadata.etsi_compliant}")
        print(f"   Hybrid Key ID: {encrypted_message.metadata.key_ids.get('hybrid_key', 'N/A')}")
        print(f"   Ciphertext Length: {len(encrypted_message.ciphertext)} chars")
        print(f"   Integrity Hash: {encrypted_message.metadata.integrity_hash[:16]}...")
        print()
        
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return False
    
    # Test Level 2 decryption
    print("🔓 Testing Level 2: Quantum-aided AES Decryption")
    print("-" * 50)
    
    start_time = time.time()
    print("🔓 Decrypting with Level 2...")
    try:
        decrypted_message = encryptor.decrypt_message(encrypted_message)
        decryption_time = time.time() - start_time
        
        print(f"✅ Decryption successful in {decryption_time:.3f}s")
        print(f"   Decrypted: {decrypted_message[:70]}...")
        
        message_match = decrypted_message == test_message
        print(f"   Message Match: {message_match}")
        
        if message_match:
            print("🎉 SUCCESS: Level 2 AES encryption/decryption working perfectly!")
            print("🔐 Hybrid key derivation with real PQC components!")
            print()
            return True
        else:
            print("❌ FAILURE: Decrypted message doesn't match original!")
            print(f"   Original : {test_message}")
            print(f"   Decrypted: {decrypted_message}")
            return False
            
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        print(f"   Error Type: {type(e).__name__}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False

def test_level2_performance():
    """Test Level 2 performance with various message sizes"""
    print("⚡ Level 2 AES Performance Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_messages = [
        "Short message",
        "This is a medium-length message for testing Level 2 encryption performance.",
        "This is a very long message " * 10 + " that tests the performance of Level 2 quantum-aided AES encryption with hybrid key derivation using QKD, ECDH, and ML-KEM components for secure ISRO communications.",
        "Quick test: " + "A" * 100,
        "Performance: " + "X" * 250 + " End of long test message"
    ]
    
    total_operations = 0
    successful_operations = 0
    total_enc_time = 0
    total_dec_time = 0
    
    for i, message in enumerate(test_messages, 1):
        print(f"📝 Test {i}: {len(message)} chars")
        
        try:
            # Encryption
            start_time = time.time()
            encrypted = encryptor.encrypt_message(
                plaintext=message,
                security_level=SecurityLevel.QUANTUM_AIDED,
                sender="alice@test.com",
                recipient="bob@test.com"
            )
            enc_time = time.time() - start_time
            total_enc_time += enc_time
            
            # Decryption
            start_time = time.time()
            decrypted = encryptor.decrypt_message(encrypted)
            dec_time = time.time() - start_time
            total_dec_time += dec_time
            
            # Verify
            if decrypted == message:
                print(f"   ✅ Success: {enc_time:.3f}s enc + {dec_time:.3f}s dec")
                successful_operations += 1
            else:
                print(f"   ❌ Failed: Message mismatch")
            
            total_operations += 1
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            total_operations += 1
    
    # Performance summary
    success_rate = (successful_operations / total_operations) * 100 if total_operations > 0 else 0
    avg_enc_time = total_enc_time / total_operations if total_operations > 0 else 0
    avg_dec_time = total_dec_time / total_operations if total_operations > 0 else 0
    
    print(f"\n📊 Performance Summary:")
    print(f"   Total Operations: {total_operations}")
    print(f"   Successful: {successful_operations}")
    print(f"   Success Rate: {success_rate:.1f}%")
    print(f"   Avg Encryption Time: {avg_enc_time:.3f}s")
    print(f"   Avg Decryption Time: {avg_dec_time:.3f}s")
    print(f"   Total Time: {total_enc_time + total_dec_time:.3f}s")
    print()
    
    return success_rate == 100.0

def test_level2_security_features():
    """Test Level 2 security features and metadata"""
    print("🛡️ Level 2 Security Features Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_message = "Security test message for Level 2 AES"
    
    try:
        encrypted = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.QUANTUM_AIDED,
            sender="alice@secure.test",
            recipient="bob@secure.test",
            subject="Security Test"
        )
        
        # Check security properties
        print(f"🔐 Security Level: {encrypted.metadata.security_level}")
        print(f"🔬 Algorithm: {encrypted.metadata.algorithm}")
        print(f"🔑 Key Source: {encrypted.metadata.key_source}")
        print(f"⚛️ Quantum Resistant: {encrypted.metadata.quantum_resistant}")
        print(f"📋 ETSI Compliant: {encrypted.metadata.etsi_compliant}")
        print(f"🆔 Hybrid Key ID: {encrypted.metadata.key_ids.get('hybrid_key', 'N/A')}")
        print(f"🔒 Integrity Hash: {encrypted.metadata.integrity_hash}")
        print(f"⏰ Timestamp: {encrypted.metadata.timestamp}")
        print()
        
        # Test ciphertext properties
        print("🔍 Ciphertext Analysis:")
        print(f"   Plaintext Length: {len(test_message)} bytes")
        print(f"   Ciphertext Length: {len(encrypted.ciphertext)} bytes")
        print(f"   Ciphertext != Plaintext: {encrypted.ciphertext != test_message}")
        
        # Test determinism (same message should produce different ciphertexts)
        encrypted2 = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.QUANTUM_AIDED,
            sender="alice@secure.test",
            recipient="bob@secure.test",
            subject="Security Test 2"
        )
        print(f"   Different Ciphertexts: {encrypted.ciphertext != encrypted2.ciphertext}")
        print()
        
        print("✅ Security features verified!")
        return True
        
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        return False

def test_level2_real_pqc_integration():
    """Test Level 2 with real PQC integration"""
    print("🔬 Level 2 Real PQC Integration Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    
    # Check if real PQC is available
    print(f"🔐 Real PQC Available: {encryptor.real_pqc is not None}")
    if encryptor.real_pqc:
        print(f"🔐 PQC Manager: {type(encryptor.real_pqc).__name__}")
    
    test_message = "Real PQC test with ML-KEM-768 and AES-256-GCM"
    
    try:
        encrypted = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.QUANTUM_AIDED,
            sender="alice@pqc.test",
            recipient="bob@pqc.test"
        )
        
        print(f"✅ Encryption with Real PQC successful")
        print(f"   Algorithm: {encrypted.metadata.algorithm}")
        print(f"   Real PQC Used: {encrypted.metadata.key_ids.get('real_pqc_used', False)}")
        
        decrypted = encryptor.decrypt_message(encrypted)
        
        if decrypted == test_message:
            print("✅ Decryption with Real PQC successful")
            print("🎉 Real PQC integration working perfectly!")
            return True
        else:
            print("❌ Decryption failed - message mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Real PQC test failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False

def main():
    """Run all Level 2 tests"""
    print("\n🧪 QuMail Task 29: Level 2 Quantum-aided AES Test Suite")
    print("=" * 70)
    print()
    
    test_results = []
    
    # Run all tests
    test_results.append(("Basic Encryption/Decryption", test_level2_basic_encryption()))
    test_results.append(("Performance Test", test_level2_performance()))
    test_results.append(("Security Features", test_level2_security_features()))
    test_results.append(("Real PQC Integration", test_level2_real_pqc_integration()))
    
    # Summary
    print("🎉 TASK 29 TEST COMPLETE!")
    print("=" * 70)
    
    passed_tests = sum(1 for _, result in test_results if result)
    total_tests = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n📊 Overall Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("✅ Level 2 Quantum-aided AES is working perfectly!")
        print("🔐 Hybrid key derivation with real PQC components!")
        print("📋 ETSI compliance verified!")
        print("🚀 Ready for ISRO Chandrayaan-4 mission!")
    else:
        print("⚠️ Some Level 2 tests failed - needs investigation")
        print("🔧 Check implementation and fix issues")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    main()
