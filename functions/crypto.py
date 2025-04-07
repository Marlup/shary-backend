# -*- coding: utf-8 -*-
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def verify(signature: bytes, message: bytes, public_key_str: str) -> bool:
    if not public_key_str:
        raise ValueError("Public key not loaded.")
    
    public_key = serialize_pubkey_from_string(public_key_str)
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def serialize_pubkey_from_string(pub_key_str: str):
    """Convert PEM or DER formatted public key string to PublicFormat object.
    Args:
        pub_key_str (str): PEM or DER formatted public key string. 
    """
    # Convert string to bytes utf8 and base64
    pub_key_der = base64.b64decode(pub_key_str.encode("utf-8")) 

    # Deserialize public key
    public_key = serialization.load_der_public_key(pub_key_der)
    
    return public_key

