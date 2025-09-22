#!/usr/bin/env python3
"""
Debug Level 1 OTP encryption/decryption
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from encryption import QuMailMultiLevelEncryption, SecurityLevel
import base64

def debug_level1():
    """Debug Level 1 OTP encryption/decryption"""
    print("🔍 Debug Level 1 OTP Encryption/Decryption")
    print("=" * 50)
    
    encryption_module = QuMailMultiLevelEncryption()
    test_message = "Hello World"
    
    print(f"📝 Test Message: '{test_message}'")
    print(f"📏 Message Length: {len(test_message)} chars")
    
    # Get QKD key for encryption
    print("\n🔐 Getting QKD key for encryption...")
    qkd_key_data = encryption_module._get_qkd_key()
    print(f"QKD Key Data: {qkd_key_data}")
    
    if 'key' in qkd_key_data:
        qkd_key = bytes.fromhex(qkd_key_data['key'])
        print(f"QKD Key (hex): {qkd_key_data['key']}")
        print(f"QKD Key (bytes): {qkd_key}")
        print(f"QKD Key Length: {len(qkd_key)} bytes")
    else:
        print("❌ No 'key' field in QKD data")
        return
    
    # Encrypt
    print("\n🔐 Encrypting...")
    encrypted_message = encryption_module.encrypt_message(
        plaintext=test_message,
        security_level=SecurityLevel.QUANTUM_SECURE,
        sender="debug@quemail.isro.gov",
        recipient="debug@quemail.isro.gov"
    )
    
    print(f"Encrypted Message ID: {encrypted_message.metadata.message_id}")
    print(f"QKD Key ID in metadata: {encrypted_message.metadata.key_ids.get('qkd_key')}")
    print(f"Ciphertext: {encrypted_message.ciphertext[:50]}...")
    
    # Get QKD key for decryption
    print("\n🔓 Getting QKD key for decryption...")
    qkd_key_id = encrypted_message.metadata.key_ids.get('qkd_key')
    print(f"Looking for QKD key ID: {qkd_key_id}")
    
    # Try to get the same key
    qkd_key_data2 = encryption_module._get_qkd_key()
    print(f"QKD Key Data (decryption): {qkd_key_data2}")
    
    if qkd_key_data2 and 'key' in qkd_key_data2:
        qkd_key2 = bytes.fromhex(qkd_key_data2['key'])
        print(f"QKD Key (hex): {qkd_key_data2['key']}")
        print(f"QKD Key (bytes): {qkd_key2}")
        print(f"QKD Key Length: {len(qkd_key2)} bytes")
        
        # Check if keys are the same
        print(f"Keys are identical: {qkd_key == qkd_key2}")
        print(f"Key IDs are identical: {qkd_key_data['key_id'] == qkd_key_data2['key_id']}")
    else:
        print("❌ No 'key' field in QKD data for decryption")
        return
    
    # Manual decryption test
    print("\n🔧 Manual decryption test...")
    ciphertext_bytes = base64.b64decode(encrypted_message.ciphertext.encode('utf-8'))
    print(f"Ciphertext length: {len(ciphertext_bytes)} bytes")
    
    # Use the same key expansion logic
    if len(ciphertext_bytes) > len(qkd_key2):
        expanded_key = encryption_module._expand_qkd_key(qkd_key2, len(ciphertext_bytes))
    else:
        expanded_key = qkd_key2[:len(ciphertext_bytes)]
    
    print(f"Expanded key length: {len(expanded_key)} bytes")
    
    # XOR decryption
    plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext_bytes, expanded_key))
    print(f"Decrypted bytes: {plaintext_bytes}")
    
    try:
        decrypted_text = plaintext_bytes.decode('utf-8')
        print(f"Decrypted text: '{decrypted_text}'")
        print(f"Decryption successful: {decrypted_text == test_message}")
    except UnicodeDecodeError as e:
        print(f"Unicode decode error: {e}")
        print(f"Raw bytes: {plaintext_bytes}")

if __name__ == "__main__":
    debug_level1()
