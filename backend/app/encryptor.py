from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
import base64
import os
import json
import secrets
from datetime import datetime, timedelta
import uuid
import logging
from typing import Dict, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global session storage (in production, use Redis or database)
sessions: Dict[str, Dict] = {}
server_keys: Optional[Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]] = None

def initialize_encryption_system():
    """Initialize the encryption system with ECC key pair"""
    global server_keys
    if server_keys is None:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        server_keys = (private_key, public_key)
        logger.info("🔑 ECC key pair generated successfully")

def get_server_public_key() -> str:
    """Get server's public key as base64 encoded SPKI format"""
    if server_keys is None:
        raise RuntimeError("Encryption system not initialized")
    public_key_bytes = server_keys[1].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes.decode()

def create_session(client_public_key: str) -> Tuple[str, datetime]:
    """Create a new session with derived keys"""
    session_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    # Import client public key
    client_pub_key = serialization.load_pem_public_key(
        client_public_key.encode(),
        backend=default_backend()
    )
    
    # Perform ECDH key exchange
    shared_key = server_keys[0].exchange(ec.ECDH(), client_pub_key)
    
    # Derive AES and HMAC keys using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for AES, 32 bytes for HMAC
        salt=None,
        info=session_id.encode(),
        backend=default_backend()
    )
    derived_key = hkdf.derive(shared_key)
    
    # Split into AES and HMAC keys
    aes_key = derived_key[:32]
    hmac_key = derived_key[32:]
    
    sessions[session_id] = {
        "client_public_key": client_public_key,
        "aes_key": aes_key,
        "hmac_key": hmac_key,
        "created_at": datetime.utcnow(),
        "expires_at": expires_at
    }
    
    return session_id, expires_at

def get_session(session_id: str) -> Optional[Dict]:
    """Retrieve active session"""
    session = sessions.get(session_id)
    if session and datetime.utcnow() < session["expires_at"]:
        return session
    return None

def cleanup_expired_sessions():
    """Remove expired sessions"""
    current_time = datetime.utcnow()
    expired = [sid for sid, sess in sessions.items() if sess["expires_at"] <= current_time]
    for sid in expired:
        del sessions[sid]

def encrypt_data(data: dict, session_keys: Dict) -> Dict[str, str]:
    """Encrypt data using AES-GCM and sign with HMAC"""
    try:
        # Generate random IV (12 bytes for GCM)
        iv = os.urandom(12)
        
        # Serialize data to JSON
        json_data = json.dumps(data).encode()
        
        # Encrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(session_keys["aes_key"]),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(json_data) + encryptor.finalize()
        tag = encryptor.tag
        
        # Create HMAC signature (iv + tag + ciphertext)
        h = hmac.HMAC(session_keys["hmac_key"], hashes.SHA256(), backend=default_backend())
        h.update(iv + tag + ciphertext)
        signature = h.finalize()
        
        return {
            "payload": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "tag": base64.b64encode(tag).decode(),
            "signature": base64.b64encode(signature).decode()
        }
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_data_with_session(encrypted_data: Dict, session_keys: Dict) -> dict:
    """Decrypt data using AES-GCM and verify HMAC"""
    try:
        # Decode base64 components
        ciphertext = base64.b64decode(encrypted_data["payload"])
        iv = base64.b64decode(encrypted_data["iv"])
        tag = base64.b64decode(encrypted_data["tag"])
        signature = base64.b64decode(encrypted_data["signature"])
        
        # Verify HMAC signature
        h = hmac.HMAC(session_keys["hmac_key"], hashes.SHA256(), backend=default_backend())
        h.update(iv + tag + ciphertext)
        h.verify(signature)
        
        # Decrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(session_keys["aes_key"]),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        return json.loads(decrypted.decode())
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise

def create_hmac_signature(data: str, hmac_key: bytes) -> str:
    """Create HMAC signature for data"""
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(data.encode())
    return base64.b64encode(h.finalize()).decode()

def verify_hmac_signature(data: str, signature: str, hmac_key: bytes) -> bool:
    """Verify HMAC signature"""
    try:
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(data.encode())
        h.verify(base64.b64decode(signature))
        return True
    except Exception:
        return False

def derive_session_keys(private_key: ec.EllipticCurvePrivateKey, public_key: str) -> Dict:
    """Derive session keys from ECDH key exchange"""
    try:
        # Import client public key
        client_pub_key = serialization.load_pem_public_key(
            public_key.encode(),
            backend=default_backend()
        )
        
        # Perform ECDH key exchange
        shared_key = private_key.exchange(ec.ECDH(), client_pub_key)
        
        # Derive keys using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"session_keys",
            backend=default_backend()
        )
        derived_key = hkdf.derive(shared_key)
        
        return {
            "aes_key": derived_key[:32],
            "hmac_key": derived_key[32:]
        }
    except Exception as e:
        logger.error(f"Key derivation failed: {str(e)}")
        raise