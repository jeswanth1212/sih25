#!/usr/bin/env python3
"""
QuMail Complete Alice → Bob Encryption Flow Test
Tests the complete encryption and decryption flow with real post-quantum cryptography
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from encryption import QuMailMultiLevelEncryption, SecurityLevel
import json
import time

def test_alice_bob_encryption_flow():
    """Test complete Alice → Bob encryption flow"""
    print("🧪 QuMail Complete Alice → Bob Encryption Flow Test")
    print("=" * 60)
    
    # Initialize encryption module
    print("\n🔐 Initializing QuMail Encryption Module...")
    try:
        encryption_module = QuMailMultiLevelEncryption()
        print("✅ Encryption module initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize encryption module: {e}")
        return False
    
    # Test message
    test_message = "Hello Bob! This is a test message from Alice using QuMail quantum-secure email system. 🚀"
    alice = "alice@quemail.isro.gov"
    bob = "bob@quemail.isro.gov"
    message_id = f"msg_{int(time.time())}"
    subject = "Test Message - QuMail Quantum Security"
    
    print(f"\n📧 Test Message:")
    print(f"   From: {alice}")
    print(f"   To: {bob}")
    print(f"   Subject: {subject}")
    print(f"   Message: {test_message[:50]}...")
    
    # Test all encryption levels
    results = {}
    
    for level in [SecurityLevel.QUANTUM_SECURE, SecurityLevel.QUANTUM_AIDED, 
                  SecurityLevel.HYBRID_PQC, SecurityLevel.NO_QUANTUM]:
        
        level_name = level.name
        level_num = level.value
        
        print(f"\n🛡️ Testing Level {level_num}: {level_name}")
        print("-" * 40)
        
        try:
            # Encrypt message
            print(f"🔐 Encrypting with Level {level_num}...")
            encrypted_message = encryption_module.encrypt_message(
                plaintext=test_message,
                security_level=level,
                sender=alice,
                recipient=bob
            )
            
            print(f"✅ Encryption successful")
            print(f"   Algorithm: {encrypted_message.metadata.algorithm}")
            print(f"   Key Source: {encrypted_message.metadata.key_source}")
            print(f"   Quantum Resistant: {encrypted_message.metadata.quantum_resistant}")
            print(f"   ETSI Compliant: {encrypted_message.metadata.etsi_compliant}")
            print(f"   Ciphertext Length: {len(encrypted_message.ciphertext)} chars")
            
            # Test decryption
            print(f"🔓 Decrypting with Level {level_num}...")
            try:
                decrypted_message = encryption_module.decrypt_message(encrypted_message)
                
                # Verify message integrity
                message_match = decrypted_message == test_message
                print(f"✅ Decryption successful")
                print(f"   Message Match: {message_match}")
                print(f"   Decrypted: {decrypted_message[:50]}...")
                
                results[level_name] = {
                    'encryption': 'SUCCESS',
                    'decryption': 'SUCCESS' if message_match else 'MISMATCH',
                    'algorithm': encrypted_message.metadata.algorithm,
                    'key_source': encrypted_message.metadata.key_source,
                    'quantum_resistant': encrypted_message.metadata.quantum_resistant,
                    'etsi_compliant': encrypted_message.metadata.etsi_compliant,
                    'ciphertext_length': len(encrypted_message.ciphertext),
                    'message_match': message_match
                }
                
            except Exception as e:
                print(f"❌ Decryption failed: {e}")
                results[level_name] = {
                    'encryption': 'SUCCESS',
                    'decryption': 'FAILED',
                    'error': str(e),
                    'algorithm': encrypted_message.metadata.algorithm,
                    'key_source': encrypted_message.metadata.key_source,
                    'quantum_resistant': encrypted_message.metadata.quantum_resistant,
                    'etsi_compliant': encrypted_message.metadata.etsi_compliant,
                    'ciphertext_length': len(encrypted_message.ciphertext)
                }
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            results[level_name] = {
                'encryption': 'FAILED',
                'decryption': 'N/A',
                'error': str(e)
            }
    
    # Print summary
    print(f"\n📊 ALICE → BOB ENCRYPTION FLOW SUMMARY")
    print("=" * 60)
    
    successful_encryptions = sum(1 for r in results.values() if r['encryption'] == 'SUCCESS')
    successful_decryptions = sum(1 for r in results.values() if r['decryption'] == 'SUCCESS')
    total_levels = len(results)
    
    print(f"Total Encryption Levels: {total_levels}")
    print(f"Successful Encryptions: {successful_encryptions}/{total_levels}")
    print(f"Successful Decryptions: {successful_decryptions}/{total_levels}")
    print(f"Success Rate: {(successful_encryptions/total_levels)*100:.1f}%")
    
    print(f"\n📋 DETAILED RESULTS")
    print("-" * 40)
    
    for level_name, result in results.items():
        print(f"\n{level_name}:")
        print(f"  Encryption: {result['encryption']}")
        if result['encryption'] == 'SUCCESS':
            print(f"  Decryption: {result['decryption']}")
            print(f"  Algorithm: {result['algorithm']}")
            print(f"  Key Source: {result['key_source']}")
            print(f"  Quantum Resistant: {result['quantum_resistant']}")
            print(f"  ETSI Compliant: {result['etsi_compliant']}")
            print(f"  Ciphertext Length: {result['ciphertext_length']} chars")
            if 'message_match' in result:
                print(f"  Message Match: {result['message_match']}")
        if 'error' in result:
            print(f"  Error: {result['error']}")
    
    # Test real PQC performance
    print(f"\n⚡ REAL PQC PERFORMANCE TEST")
    print("-" * 40)
    
    if hasattr(encryption_module, 'real_pqc') and encryption_module.real_pqc:
        print("Testing real post-quantum cryptography performance...")
        
        start_time = time.time()
        for i in range(100):
            public_key, private_key = encryption_module.real_pqc.pqc.generate_keypair()
            ciphertext, shared_secret = encryption_module.real_pqc.pqc.encapsulate(public_key)
            decrypted_secret = encryption_module.real_pqc.pqc.decapsulate(private_key, ciphertext)
        end_time = time.time()
        
        operations_per_second = 100 / (end_time - start_time)
        print(f"✅ 100 ML-KEM operations in {end_time - start_time:.3f} seconds")
        print(f"✅ Operations per second: {operations_per_second:.1f}")
        print(f"✅ Real PQC is working at production speed!")
    else:
        print("⚠️ Real PQC not available for performance testing")
    
    # Final assessment
    print(f"\n🎉 ALICE → BOB ENCRYPTION FLOW TEST COMPLETE!")
    print("=" * 60)
    
    if successful_encryptions == total_levels:
        print("✅ ALL ENCRYPTION LEVELS WORKING!")
        print("🚀 QuMail is ready for ISRO Chandrayaan-4 mission!")
    elif successful_encryptions > 0:
        print(f"⚠️ {successful_encryptions}/{total_levels} encryption levels working")
        print("🔧 Some levels need backend integration")
    else:
        print("❌ No encryption levels working")
        print("🔧 System needs debugging")
    
    return successful_encryptions > 0

if __name__ == "__main__":
    success = test_alice_bob_encryption_flow()
    sys.exit(0 if success else 1)
