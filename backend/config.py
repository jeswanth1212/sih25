# QuMail Backend Configuration
# Configuration file for Firebase Realtime Database integration

import os
from typing import Dict, Any

class Config:
    """
    Configuration class for QuMail backend services
    """
    
    # Firebase Configuration
    # NOTE: These values need to be filled manually after creating Firebase project
    FIREBASE_CONFIG = {
        'apiKey': '',  # TODO: Add your Firebase API key
        'authDomain': '',  # TODO: Add your Firebase auth domain  
        'databaseURL': '',  # TODO: Add your Firebase Realtime Database URL
        'projectId': '',  # TODO: Add your Firebase project ID
        'storageBucket': '',  # TODO: Add your Firebase storage bucket
        'messagingSenderId': '',  # TODO: Add your Firebase messaging sender ID
        'appId': ''  # TODO: Add your Firebase app ID
    }
    
    # QKD Configuration
    QKD_CONFIG = {
        'key_length': 256,  # bits
        'error_rate_threshold': 0.15,  # 15% max error rate for eavesdropping detection
        'bb84_basis_count': 1024,  # Number of basis states for BB84 simulation
        'etsi_compliance': True  # ETSI GS QKD 014 standard compliance
    }
    
    # Encryption Configuration  
    ENCRYPTION_CONFIG = {
        'aes_key_size': 256,  # AES-256
        'ml_kem_variant': 768,  # ML-KEM-768
        'ml_dsa_variant': '6x5',  # ML-DSA-6x5
        'kdf_algorithm': 'sha256',  # KDF2 with SHA-256
        'ecdh_curve': 'X25519'  # ECDH curve
    }
    
    # Email Configuration
    EMAIL_CONFIG = {
        'smtp_timeout': 30,  # seconds
        'imap_timeout': 30,  # seconds
        'max_attachment_size': 25 * 1024 * 1024,  # 25MB
        'supported_providers': ['gmail', 'yahoo']
    }
    
    # Flask Configuration
    FLASK_CONFIG = {
        'host': '127.0.0.1',
        'port': 5000,
        'debug': True,  # Set to False in production
        'ssl_context': None  # Will be configured for mTLS
    }

class FirebaseSetup:
    """
    Helper class for Firebase initialization
    """
    
    @staticmethod
    def validate_config(config: Dict[str, Any]) -> bool:
        """
        Validate Firebase configuration
        """
        required_fields = [
            'apiKey', 'authDomain', 'databaseURL', 
            'projectId', 'storageBucket', 'messagingSenderId', 'appId'
        ]
        
        for field in required_fields:
            if not config.get(field):
                print(f"Missing Firebase configuration: {field}")
                return False
        return True
    
    @staticmethod
    def initialize_firebase(config: Dict[str, Any]):
        """
        Initialize Firebase Admin SDK
        """
        try:
            import firebase_admin
            from firebase_admin import credentials, db
            
            # Initialize Firebase Admin SDK
            if not firebase_admin._apps:
                # In production, use service account key file
                # For development, using default credentials
                cred = credentials.ApplicationDefault()
                firebase_admin.initialize_app(cred, {
                    'databaseURL': config['databaseURL']
                })
            
            return db.reference()
            
        except Exception as e:
            print(f"Firebase initialization error: {e}")
            return None

# Environment-based configuration loading
def load_config():
    """
    Load configuration based on environment
    """
    env = os.getenv('QUMAIL_ENV', 'development')
    
    if env == 'production':
        # Load production config
        Config.FLASK_CONFIG['debug'] = False
        Config.FLASK_CONFIG['ssl_context'] = 'adhoc'  # Enable SSL
    
    return Config

# Export configuration instance
config = load_config()
