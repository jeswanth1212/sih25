#!/usr/bin/env python3
"""
Simple Integration Test (No Unicode)
Tests all components working together as a unified system
"""

import requests
import json
import time

def test_integration_simple():
    """Test complete system integration without Unicode characters"""
    print("QuMail Complete Integration Test")
    print("=" * 60)
    
    base_url = "http://127.0.0.1:5000"
    
    # Test 1: System Overview
    print("\nTest 1: System Overview")
    try:
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            system_info = response.json()
            print(f"Service: {system_info['service']}")
            print(f"Standards: {', '.join(system_info['standards'])}")
            print(f"Components Available: {all(system_info['components'].values())}")
            print(f"All Components: {system_info['components']}")
        else:
            print(f"System overview failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"System overview error: {str(e)}")
        return False
    
    # Test 2: Cross-Component Integration
    print("\nTest 2: Cross-Component Integration")
    
    try:
        # Generate components from each system
        print("  Generating QKD key...")
        qkd_response = requests.post(f"{base_url}/api/qkd/generate")
        if qkd_response.status_code != 201:
            print(f"QKD key generation failed: {qkd_response.status_code}")
            return False
        qkd_key = qkd_response.json()['key_data']
        print(f"  QKD Key: {qkd_key['key_id']}")
        
        print("  Generating ECDH keypair...")
        ecdh_response = requests.post(f"{base_url}/api/ecdh/keypair", 
                                    json={"key_id": "integration_ecdh"})
        if ecdh_response.status_code != 201:
            print(f"ECDH keypair generation failed: {ecdh_response.status_code}")
            return False
        ecdh_keypair = ecdh_response.json()
        print(f"  ECDH Keypair: {ecdh_keypair['key_id']}")
        
        print("  Generating ML-KEM keypair...")
        mlkem_response = requests.post(f"{base_url}/api/mlkem/keypair", 
                                     json={"key_id": "integration_mlkem"})
        if mlkem_response.status_code != 201:
            print(f"ML-KEM keypair generation failed: {mlkem_response.status_code}")
            return False
        mlkem_keypair = mlkem_response.json()
        print(f"  ML-KEM Keypair: {mlkem_keypair['key_id']}")
        
        # Generate ECDH shared secret
        print("  Computing ECDH shared secret...")
        ecdh_exchange_response = requests.post(f"{base_url}/api/ecdh/exchange", json={
            "local_key_id": ecdh_keypair['key_id'],
            "remote_public_key": ecdh_keypair['public_key'],  # Self-exchange for demo
            "shared_secret_id": "integration_ecdh_shared"
        })
        if ecdh_exchange_response.status_code != 201:
            print(f"ECDH shared secret failed: {ecdh_exchange_response.status_code}")
            return False
        ecdh_shared = ecdh_exchange_response.json()
        print(f"  ECDH Shared Secret: {ecdh_shared['shared_secret_id']}")
        
        # Generate ML-KEM shared secret
        print("  Computing ML-KEM shared secret...")
        mlkem_encaps_response = requests.post(f"{base_url}/api/mlkem/encapsulate", json={
            "remote_public_key": mlkem_keypair['public_key'],
            "secret_id": "integration_mlkem_shared"
        })
        if mlkem_encaps_response.status_code != 201:
            print(f"ML-KEM shared secret failed: {mlkem_encaps_response.status_code}")
            return False
        mlkem_shared = mlkem_encaps_response.json()
        print(f"  ML-KEM Shared Secret: {mlkem_shared['secret_id']}")
        
        # Derive hybrid key using all components
        print("  Deriving hybrid key from all components...")
        hybrid_response = requests.post(f"{base_url}/api/hybrid/derive", json={
            "key_id": "integration_hybrid_key",
            "qkd_key_id": qkd_key['key_id'],
            "ecdh_shared_secret_id": ecdh_shared['shared_secret_id'],
            "mlkem_shared_secret_id": mlkem_shared['secret_id']
        })
        if hybrid_response.status_code != 201:
            print(f"Hybrid key derivation failed: {hybrid_response.status_code}")
            return False
        hybrid_key = hybrid_response.json()
        print(f"  Hybrid Key: {hybrid_key['hybrid_key_id']}")
        print(f"  Security Level: {hybrid_key['security_level']}")
        print(f"  Components: {hybrid_key['components']}")
        print(f"  Key Length: {hybrid_key['key_length']} bits")
        
    except Exception as e:
        print(f"Cross-component integration error: {str(e)}")
        return False
    
    # Test 3: System Stress Test
    print("\nTest 3: System Stress Test")
    
    try:
        # Generate multiple keys rapidly
        print("  Generating multiple keys rapidly...")
        for i in range(3):
            # QKD key
            requests.post(f"{base_url}/api/qkd/generate")
            # ECDH keypair
            requests.post(f"{base_url}/api/ecdh/keypair", 
                         json={"key_id": f"stress_ecdh_{i}"})
            # ML-KEM keypair
            requests.post(f"{base_url}/api/mlkem/keypair", 
                         json={"key_id": f"stress_mlkem_{i}"})
        
        # Check system status
        print("  Checking system status after stress...")
        qkd_status = requests.get(f"{base_url}/api/qkd/status").json()
        ecdh_status = requests.get(f"{base_url}/api/ecdh/status").json()
        mlkem_status = requests.get(f"{base_url}/api/mlkem/status").json()
        hybrid_status = requests.get(f"{base_url}/api/hybrid/keys").json()
        
        print(f"  QKD Keys: {qkd_status['active_keys']}")
        print(f"  ECDH Keypairs: {ecdh_status['active_keypairs']}")
        print(f"  ML-KEM Keypairs: {mlkem_status['active_keypairs']}")
        print(f"  Hybrid Keys: {hybrid_status['count']}")
        
    except Exception as e:
        print(f"Stress test error: {str(e)}")
        return False
    
    # Test 4: Final System Health Check
    print("\nTest 4: Final System Health Check")
    
    try:
        # Check all component statuses
        components = ['qkd', 'ecdh', 'mlkem', 'hybrid']
        all_healthy = True
        
        for component in components:
            if component == 'hybrid':
                response = requests.get(f"{base_url}/api/{component}/keys")
                status = "operational" if response.status_code == 200 else "error"
            else:
                response = requests.get(f"{base_url}/api/{component}/status")
                status = response.json().get('status', 'error') if response.status_code == 200 else 'error'
            
            print(f"  {component.upper()}: {status}")
            if status != 'operational':
                all_healthy = False
        
        if all_healthy:
            print("  All components healthy!")
        else:
            print("  Some components unhealthy!")
            return False
            
    except Exception as e:
        print(f"Health check error: {str(e)}")
        return False
    
    # Summary
    print("\nINTEGRATION TEST SUMMARY")
    print("=" * 40)
    print("System Overview: PASSED")
    print("Cross-Component Integration: PASSED")
    print("System Stress Test: PASSED")
    print("Final Health Check: PASSED")
    
    print("\nCOMPLETE INTEGRATION TEST: ALL TESTS PASSED!")
    print("QuMail Hybrid Quantum-Classical System: FULLY OPERATIONAL!")
    print("Ready for ISRO Smart India Hackathon 2025!")
    
    return True

if __name__ == "__main__":
    success = test_integration_simple()
    exit(0 if success else 1)
