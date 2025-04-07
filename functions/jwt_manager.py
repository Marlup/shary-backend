import logging
import secrets
import jwt
import datetime
from typing import Optional, Dict
from constants import ALGORITHM, DEFAULT_EXPIRE_TIME

class JWTManager:

    def __init__(self, secret_key: Optional[str] = None, expires_in_minutes: int = 60 * 24 * 30):
        #self.secret_key = secret_key or self.generate_secret_key()
        self.algorithm = ALGORITHM
        self.expires_in = datetime.timedelta(minutes=expires_in_minutes)

    @staticmethod
    def create_token(owner: str, secret_key: str, additional_claims: Optional[Dict] = None) -> str:
        """Create a JWT token with optional additional claims."""
        expires_in = datetime.timedelta(minutes=DEFAULT_EXPIRE_TIME)
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": owner,
            "iat": now,
            "exp": now + expires_in
        }
        if additional_claims:
            payload.update(additional_claims)
        new_token = jwt.encode(payload, secret_key, algorithm=ALGORITHM).strip()
        print(f"create_token - token: {new_token}")
        print(f"create_token - secret_key: {secret_key}")
        return new_token

    @staticmethod
    def decode_token(token: str, secret_key: str) -> Dict:
        """Decode a JWT token and return its payload."""
        return JWTManager._decode_token(token, secret_key)

    @staticmethod
    def is_token_valid(token: str, secret_key: str) -> bool:
        """Check if a token is valid and not expired."""
        try:
            JWTManager._decode_token(token, secret_key)
            return True
        except Exception:
            return False

    @staticmethod
    def generate_secret_key(length: int = 32) -> str:
        """Generate a random secret key."""
        return secrets.token_hex(length)

    @staticmethod
    def _decode_token(token: str, secret_key: str) -> Dict:
        """Internal method to decode and validate token."""
        print(f"_decode_token - token: {token}")
        print(f"_decode_token - secret_key: {secret_key}")

        try:
            return jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired.")
        except jwt.InvalidAlgorithmError:
            raise ValueError("Invalid algorithm.")
        except jwt.InvalidAudienceError:
            raise ValueError("Invalid audience.")
        except jwt.InvalidKeyError:
            raise ValueError("Invalid Key.")
        except jwt.MissingRequiredClaimError:
            raise ValueError("Missing required claim.")
        except jwt.ImmatureSignatureError:
            raise ValueError("Immature signature.")
        except jwt.DecodeError:
            raise ValueError("Failure at decoding.")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token.")
