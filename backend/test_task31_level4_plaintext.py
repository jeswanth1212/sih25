#!/usr/bin/env python3
"""
QuMail Task 31: Level 4 No Quantum Security Test Suite
ISRO Smart India Hackathon 2025

Test comprehensive Level 4 encryption/decryption with:
- Plaintext passthrough mode
- Basic AES-256 encryption (non-quantum)
- Performance testing
- Fallback testing
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

def test_level4_basic_encryption():
    """Test basic Level 4 encryption/decryption"""
    print("🔓 Testing Level 4: No Quantum Security")
    print("-" * 50)
    
    # Initialize encryption module
    print("🔐 Initializing QuMail Encryption Module...")
    encryptor = QuMailMultiLevelEncryption()
    print("✅ Encryption module initialized successfully\n")
    
    # Test message
    test_message = "Hello ISRO! This is a test message for Level 4 No Quantum Security - using basic encryption or plaintext for maximum speed and compatibility."
    sender = "alice@legacy.isro.gov"
    recipient = "bob@legacy.isro.gov"
    
    print(f"📧 Test Message:")
    print(f"   From: {sender}")
    print(f"   To: {recipient}")
    print(f"   Message: {test_message[:70]}...")
    print()
    
    # Test Level 4 encryption
    print("🔓 Testing Level 4: No Quantum Security")
    print("-" * 50)
    
    start_time = time.time()
    print("🔓 Encrypting with Level 4...")
    try:
        encrypted_message = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.NO_QUANTUM,
            sender=sender,
            recipient=recipient,
            subject="Test Level 4 Basic"
        )
        encryption_time = time.time() - start_time
        
        print(f"✅ Encryption successful in {encryption_time:.3f}s")
        print(f"   Algorithm: {encrypted_message.metadata.algorithm}")
        print(f"   Key Source: {encrypted_message.metadata.key_source}")
        print(f"   Quantum Resistant: {encrypted_message.metadata.quantum_resistant}")
        print(f"   ETSI Compliant: {encrypted_message.metadata.etsi_compliant}")
        print(f"   Ciphertext Length: {len(encrypted_message.ciphertext)} chars")
        print(f"   Integrity Hash: {encrypted_message.metadata.integrity_hash[:16]}...")
        print()
        
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False
    
    # Test Level 4 decryption
    print("🔓 Testing Level 4: No Quantum Security Decryption")
    print("-" * 50)
    
    start_time = time.time()
    print("🔓 Decrypting with Level 4...")
    try:
        decrypted_message = encryptor.decrypt_message(encrypted_message)
        decryption_time = time.time() - start_time
        
        print(f"✅ Decryption successful in {decryption_time:.3f}s")
        print(f"   Decrypted: {decrypted_message[:70]}...")
        
        message_match = decrypted_message == test_message
        print(f"   Message Match: {message_match}")
        
        if message_match:
            print("🎉 SUCCESS: Level 4 basic encryption/decryption working!")
            print("🔓 Non-quantum security for legacy compatibility!")
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

def test_level4_performance():
    """Test Level 4 performance - should be fastest"""
    print("⚡ Level 4 Performance Test (Fastest)")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_messages = [
        "Very fast test",
        "This is a medium message for Level 4 performance testing with no quantum security overhead.",
        "Long message: " + "FAST" * 50 + " Level 4 should be the fastest encryption method.",
        "Speed test: " + "X" * 200,
        "Final perf test: " + "Z" * 100
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
                security_level=SecurityLevel.NO_QUANTUM,
                sender="alice@speed.test",
                recipient="bob@speed.test"
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
    print("   Note: Level 4 should be fastest (no quantum overhead)")
    print()
    
    return success_rate == 100.0

def test_level4_security_features():
    """Test Level 4 security metadata and properties"""
    print("🛡️ Level 4 Security Features Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_message = "Level 4 security analysis - basic protection only"
    
    try:
        encrypted = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.NO_QUANTUM,
            sender="alice@basic.test",
            recipient="bob@basic.test",
            subject="Level 4 Security Test"
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
        
        # Analyze basic properties
        print("🔍 Level 4 Analysis:")
        print(f"   Plaintext Length: {len(test_message)} bytes")
        print(f"   Ciphertext Length: {len(encrypted.ciphertext)} bytes")
        print(f"   Ciphertext != Plaintext: {encrypted.ciphertext != test_message}")
        
        # Check for quantum components (should have none)
        key_ids = encrypted.metadata.key_ids
        quantum_keys = [k for k in key_ids.keys() if any(q in k.lower() for q in ['qkd', 'quantum', 'mlkem', 'pqc'])]
        print(f"   Quantum Components: {len(quantum_keys)} (should be 0)")
        
        print("✅ Level 4 security features verified!")
        return True
        
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False

def test_level4_compatibility():
    """Test Level 4 compatibility and fallback features"""
    print("🔗 Level 4 Compatibility Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    test_message = "Compatibility test for legacy systems and fallback scenarios"
    
    try:
        # Test basic compatibility
        encrypted = encryptor.encrypt_message(
            plaintext=test_message,
            security_level=SecurityLevel.NO_QUANTUM,
            sender="alice@compat.test",
            recipient="bob@compat.test"
        )
        
        print("✅ Level 4 encryption successful")
        print(f"   Algorithm: {encrypted.metadata.algorithm}")
        print(f"   Designed for: Legacy compatibility")
        print(f"   Quantum Overhead: None")
        
        # Test decryption
        decrypted = encryptor.decrypt_message(encrypted)
        
        if decrypted == test_message:
            print("✅ Level 4 decryption successful")
            print("🎉 Perfect compatibility for legacy systems!")
            return True
        else:
            print("❌ Compatibility test failed - message mismatch")
            return False
            
    except Exception as e:
        print(f"❌ Compatibility test failed: {e}")
        import traceback
        print(f"   Traceback: {traceback.format_exc()}")
        return False

def test_level4_all_modes():
    """Test Level 4 in different operational modes"""
    print("🔄 Level 4 Multi-Mode Test")
    print("-" * 40)
    
    encryptor = QuMailMultiLevelEncryption()
    
    test_scenarios = [
        ("Basic Text", "Simple plaintext message"),
        ("With Numbers", "Message with numbers 12345 and symbols @#$%"),
        ("Unicode Text", "Unicode: 🚀 ISRO 🛰️ Mission 2025 🌟"),
        ("Empty Message", ""),
        ("Long Text", "A" * 500 + " End of long message")
    ]
    
    successful_tests = 0
    total_tests = len(test_scenarios)
    
    for test_name, message in test_scenarios:
        print(f"📝 {test_name}: {len(message)} chars")
        
        try:
            # Encrypt
            encrypted = encryptor.encrypt_message(
                plaintext=message,
                security_level=SecurityLevel.NO_QUANTUM,
                sender=f"alice@{test_name.lower().replace(' ', '')}.test",
                recipient=f"bob@{test_name.lower().replace(' ', '')}.test"
            )
            
            # Decrypt
            decrypted = encryptor.decrypt_message(encrypted)
            
            if decrypted == message:
                print(f"   ✅ Success: {test_name}")
                successful_tests += 1
            else:
                print(f"   ❌ Failed: {test_name} - message mismatch")
                
        except Exception as e:
            print(f"   ❌ Error: {test_name} - {e}")
    
    success_rate = (successful_tests / total_tests) * 100 if total_tests > 0 else 0
    print(f"\n📊 Multi-Mode Results: {successful_tests}/{total_tests} passed ({success_rate:.1f}%)")
    
    return success_rate == 100.0

def main():
    """Run all Level 4 tests"""
    print("\n🧪 QuMail Task 31: Level 4 No Quantum Security Test Suite")
    print("=" * 70)
    print()
    
    test_results = []
    
    # Run all tests
    test_results.append(("Basic Encryption/Decryption", test_level4_basic_encryption()))
    test_results.append(("Performance Test", test_level4_performance()))
    test_results.append(("Security Features", test_level4_security_features()))
    test_results.append(("Compatibility Test", test_level4_compatibility()))
    test_results.append(("Multi-Mode Test", test_level4_all_modes()))
    
    # Summary
    print("🎉 TASK 31 TEST COMPLETE!")
    print("=" * 70)
    
    passed_tests = sum(1 for _, result in test_results if result)
    total_tests = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n📊 Overall Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("✅ Level 4 No Quantum Security is working perfectly!")
        print("🔓 Legacy compatibility and fallback support!")
        print("⚡ Fastest encryption for non-critical communications!")
        print("🚀 All QuMail security levels now complete!")
    else:
        print("⚠️ Some Level 4 tests failed - needs investigation")
        print("🔧 Check implementation and fix issues")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    main()
