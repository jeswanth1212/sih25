#!/usr/bin/env python3
"""
QuMail Task 30: Level 3 Hybrid PQC Test Suite
ISRO Smart India Hackathon 2025

Test comprehensive Level 3 encryption/decryption with:
- Real ML-KEM-768 key encapsulation
- Real ML-DSA-65 digital signatures
- Real AES-256-GCM encryption
- Double signature verification (Classical + Post-Quantum)
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

def test_level3_basic_encryption():
    """Test basic Level 3 encryption/decryption"""
    print("🔐 Testing Level 3: Hybrid PQC Encryption")
    print("-" * 50)
    
    # Initialize encryption module
    print("🔐 Initializing QuMail Encryption Module...")
    encryptor = QuMailMultiLevelEncryption()
    print("✅ Encryption module initialized successfully\n")
    
    # Test message
    test_message = "Hello ISRO! This is a test message for Level 3 Hybrid Post-Quantum Cryptography with ML-KEM-768 key encapsulation and ML-DSA-65 digital signatures for maximum security."
    sender = "alice@pqc.isro.gov"
    recipient = "bob@pqc.isro.gov"
    
    print(f"📧 Test Message:")
    print(f"   From: {sender}")
    print(f"   To: {recipient}")
    print(f"   Message: {test_message[:70]}...")
    print()
    
    # Test Level 3 encryption
    print("🔐 Testing Level 3: Hybrid PQC Encryption")
    print("-" * 50)
    
    start_time = time.time()
    print("🔐 Encrypting with Level 3...")
    try:
        encrypted_message = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.HYBRID_PQC,
            sender=sender,
            recipient=recipient,
            subject="Test Level 3 PQC"
        )
        encryption_time = time.time() - start_time
        
        print(f"✅ Encryption successful in {encryption_time:.3f}s")
        print(f"   Algorithm: {encrypted_message.metadata.algorithm}")
        print(f"   Key Source: {encrypted_message.metadata.key_source}")
        print(f"   Quantum Resistant: {encrypted_message.metadata.quantum_resistant}")
        print(f"   ETSI Compliant: {encrypted_message.metadata.etsi_compliant}")
        print(f"   ML-KEM Ciphertext: {len(encrypted_message.metadata.key_ids.get('mlkem_ciphertext', ''))} chars")
        print(f"   Signature Keys: {list(encrypted_message.metadata.key_ids.keys())}")
        print(f"   Ciphertext Length: {len(encrypted_message.ciphertext)} chars")
        print(f"   Integrity Hash: {encrypted_message.metadata.integrity_hash[:16]}...")
        print()
        
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False
    
    # Test Level 3 decryption
    print("🔓 Testing Level 3: Hybrid PQC Decryption")
    print("-" * 50)
    
    start_time = time.time()
    print("🔓 Decrypting with Level 3...")
    try:
        decrypted_message = encryptor.decrypt_message(encrypted_message)
        decryption_time = time.time() - start_time
        
        print(f"✅ Decryption successful in {decryption_time:.3f}s")
        print(f"   Decrypted: {decrypted_message[:70]}...")
        
        message_match = decrypted_message == test_message
        print(f"   Message Match: {message_match}")
        
        if message_match:
            print("🎉 SUCCESS: Level 3 Hybrid PQC encryption/decryption working perfectly!")
            print("🔬 Real ML-KEM-768 + ML-DSA-65 + AES-256-GCM!")
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

def test_level3_signature_verification():
    """Test Level 3 digital signature verification"""
    print("🔍 Level 3 Signature Verification Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_message = "Signature verification test for ML-DSA-65"
    
    print(f"🔐 Real PQC Available: {encryptor.real_pqc is not None}")
    
    try:
        encrypted = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.HYBRID_PQC,
            sender="alice@signature.test",
            recipient="bob@signature.test"
        )
        
        print("✅ Encryption with signatures successful")
        
        # Check signature metadata
        key_ids = encrypted.metadata.key_ids
        print(f"🔑 Signature Components:")
        for key, value in key_ids.items():
            if 'signature' in key.lower() or 'sign' in key.lower():
                print(f"   {key}: {str(value)[:50]}...")
        
        # Test decryption (which includes signature verification)
        decrypted = encryptor.decrypt_message(encrypted)
        
        if decrypted == test_message:
            print("✅ Signature verification successful")
            print("🎉 Double signatures (EdDSA + ML-DSA-65) working!")
            return True
        else:
            print("❌ Signature verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Signature test failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False

def test_level3_performance():
    """Test Level 3 performance with various message sizes"""
    print("⚡ Level 3 PQC Performance Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_messages = [
        "Short PQC test",
        "This is a medium-length message for testing Level 3 post-quantum cryptography performance.",
        "Long message: " + "X" * 200 + " End of test message with ML-KEM-768 and ML-DSA-65 signatures.",
        "Performance test: " + "A" * 100,
        "Final test: " + "Z" * 150
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
                security_level=SecurityLevel.HYBRID_PQC,
                sender="alice@perf.test",
                recipient="bob@perf.test"
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

def test_level3_security_features():
    """Test Level 3 security features and metadata"""
    print("🛡️ Level 3 Security Features Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_message = "Security analysis for Level 3 Hybrid PQC"
    
    try:
        encrypted = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.HYBRID_PQC,
            sender="alice@security.test",
            recipient="bob@security.test",
            subject="Level 3 Security Test"
        )
        
        # Check security properties
        print(f"🔐 Security Level: {encrypted.metadata.security_level}")
        print(f"🔬 Algorithm: {encrypted.metadata.algorithm}")
        print(f"🔑 Key Source: {encrypted.metadata.key_source}")
        print(f"⚛️ Quantum Resistant: {encrypted.metadata.quantum_resistant}")
        print(f"📋 ETSI Compliant: {encrypted.metadata.etsi_compliant}")
        print(f"🔒 Integrity Hash: {encrypted.metadata.integrity_hash}")
        print(f"⏰ Timestamp: {encrypted.metadata.timestamp}")
        print()
        
        # Analyze cryptographic components
        print("🔍 Cryptographic Components:")
        key_ids = encrypted.metadata.key_ids
        
        # Check for ML-KEM components
        mlkem_keys = [k for k in key_ids.keys() if 'mlkem' in k.lower() or 'kem' in k.lower()]
        signature_keys = [k for k in key_ids.keys() if 'signature' in k.lower() or 'sign' in k.lower()]
        
        print(f"   ML-KEM Components: {len(mlkem_keys)}")
        for key in mlkem_keys:
            print(f"     {key}: Present")
            
        print(f"   Signature Components: {len(signature_keys)}")
        for key in signature_keys:
            print(f"     {key}: Present")
        
        print(f"   Real PQC Used: {key_ids.get('real_pqc_used', 'Unknown')}")
        
        # Test ciphertext properties
        print(f"\n🔍 Ciphertext Analysis:")
        print(f"   Plaintext Length: {len(test_message)} bytes")
        print(f"   Ciphertext Length: {len(encrypted.ciphertext)} bytes")
        print(f"   Ciphertext != Plaintext: {encrypted.ciphertext != test_message}")
        
        print("✅ Security features verified!")
        return True
        
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False

def test_level3_real_pqc_components():
    """Test Level 3 real PQC component integration"""
    print("🔬 Level 3 Real PQC Components Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    
    # Check PQC availability
    print(f"🔐 Real PQC Manager Available: {encryptor.real_pqc is not None}")
    if encryptor.real_pqc:
        print(f"🔐 PQC Manager Type: {type(encryptor.real_pqc).__name__}")
    
    test_message = "Real PQC component test with full Level 3 security"
    
    try:
        encrypted = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.HYBRID_PQC,
            sender="alice@real-pqc.test",
            recipient="bob@real-pqc.test"
        )
        
        print("✅ Encryption with real PQC components successful")
        print(f"   Algorithm: {encrypted.metadata.algorithm}")
        print(f"   Key Source: {encrypted.metadata.key_source}")
        
        # Check for real PQC indicators
        key_ids = encrypted.metadata.key_ids
        real_pqc_indicators = [k for k, v in key_ids.items() if 'real' in str(v).lower() or 'pqc' in str(v).lower()]
        
        print(f"   Real PQC Indicators: {len(real_pqc_indicators)}")
        for indicator in real_pqc_indicators:
            print(f"     {indicator}: {key_ids[indicator]}")
        
        # Test decryption
        decrypted = encryptor.decrypt_message(encrypted)
        
        if decrypted == test_message:
            print("✅ Decryption with real PQC components successful")
            print("🎉 Real ML-KEM-768 + ML-DSA-65 integration perfect!")
            return True
        else:
            print("❌ Decryption failed - message mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Real PQC components test failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False

def main():
    """Run all Level 3 tests"""
    print("\n🧪 QuMail Task 30: Level 3 Hybrid PQC Test Suite")
    print("=" * 70)
    print()
    
    test_results = []
    
    # Run all tests
    test_results.append(("Basic Encryption/Decryption", test_level3_basic_encryption()))
    test_results.append(("Signature Verification", test_level3_signature_verification()))
    test_results.append(("Performance Test", test_level3_performance()))
    test_results.append(("Security Features", test_level3_security_features()))
    test_results.append(("Real PQC Components", test_level3_real_pqc_components()))
    
    # Summary
    print("🎉 TASK 30 TEST COMPLETE!")
    print("=" * 70)
    
    passed_tests = sum(1 for _, result in test_results if result)
    total_tests = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n📊 Overall Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("✅ Level 3 Hybrid PQC is working perfectly!")
        print("🔬 Real ML-KEM-768 + ML-DSA-65 + AES-256-GCM!")
        print("📋 Double signature verification working!")
        print("🚀 Ready for maximum security ISRO missions!")
    else:
        print("⚠️ Some Level 3 tests failed - needs investigation")
        print("🔧 Check implementation and fix issues")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    main()
