from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# 1. Generate RSA Keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8
# serialization.BestAvailableEncryption(password), serialization.NoEncryption()

# 2.1. Save Private Keys to Files
def save_private_key_encrypted(private_key, path="private_key.pem", password=b"strongpassword"):
    # Private Key
    encrypted = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(path, "wb") as f:
        f.write(encrypted)

# 2.2.
def save_public_key(public_key, path="public_key.pem"):
    # Public Key Pem bytes
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(path, "wb") as f:
        f.write(public_key_pem)

# 3.1. Load private Keys with password
# Load private key with password
def load_private_key_encrypted(path="private_key.pem", password=b"strongpassword"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=password,
            backend=default_backend()
        )
# 3.2
def load_public_key(path="public_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )


# 4. Encrypt with Public Key
def encrypt_message(public_key, message: str) -> bytes:
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# 5. Decrypt with Private Key
def decrypt_message(private_key, encrypted_data: bytes) -> str:
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# 🔁 Example usage
if __name__ == "__main__":
    priv, pub = generate_keys()
    save_private_key_encrypted(priv, password=b"strongpassword")
    save_public_key(pub)

    priv_loaded = load_private_key_encrypted()
    pub_loaded = load_public_key()

    encrypted = encrypt_message(pub_loaded, "Hello, RSA encryption!")
    print("Encrypted:", encrypted)

    decrypted = decrypt_message(priv_loaded, encrypted)
    print("Decrypted:", decrypted)
