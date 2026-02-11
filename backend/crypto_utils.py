import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# --- [REQUIREMENT: Encryption - Key Exchange/Generation] ---
# Implementation: Automated secure key generation (AES & RSA Keypairs)
class AESCipher:
    def __init__(self, key_path='aes.key'):
        # PRODUCTION: Key should be in ENV or Vault. 
        # PROTOTYPE: Persist to file to survive restarts.
        
        self.key = os.environ.get('AES_KEY')
        
        if not self.key:
            if os.path.exists(key_path):
                with open(key_path, 'rb') as f:
                    self.key = f.read()
            else:
                # --- [REQUIREMENT: Encryption - AES] ---
                # Implementation: AES key generation for Fernet
                self.key = Fernet.generate_key()
                with open(key_path, 'wb') as f:
                    f.write(self.key)
                print(f"WARNING: Generated new AES key and saved to {key_path}")
        
        if isinstance(self.key, str):
            self.key = self.key.encode()
            
        # --- [REQUIREMENT: Encryption - AES] ---
        # Implementation: Fernet (AES-based) cipher initialization
        self.cipher = Fernet(self.key)

# --- [REQUIREMENT: Encryption & Decryption] ---
# Implementation: AES (Symmetric) for bulk data encryption (Fernet)
    def encrypt(self, data):
        """Encrypts string or dict data."""
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        if isinstance(data, str):
            data = data.encode()
        # --- [REQUIREMENT: Encryption - AES] ---
        # Implementation: Fernet encryption
        return self.cipher.encrypt(data).decode()

    def decrypt(self, token):
        """Decrypts to string or dict."""
        try:
            if isinstance(token, str):
                token = token.encode()
            # --- [REQUIREMENT: Encryption - AES] ---
            # Implementation: Fernet decryption
            decrypted_data = self.cipher.decrypt(token).decode()
            try:
                return json.loads(decrypted_data)
            except json.JSONDecodeError:
                return decrypted_data
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

class RSASigner:
    def __init__(self, key_dir='keys'):
        self.key_dir = key_dir
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
        
        # Check if keys exist, if not generate
        if not (os.path.exists(os.path.join(key_dir, 'private_key.pem')) and 
                os.path.exists(os.path.join(key_dir, 'public_key.pem'))):
            self._generate_keys()
        
        self._load_keys()

    def _generate_keys(self):
        print("Generating new RSA Keypair...")
        # --- [REQUIREMENT: Encryption - RSA] ---
        # Implementation: RSA key pair generation
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Save Private Key
        with open(os.path.join(self.key_dir, 'private_key.pem'), 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save Public Key
        public_key = private_key.public_key()
        with open(os.path.join(self.key_dir, 'public_key.pem'), 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def _load_keys(self):
        # --- [REQUIREMENT: Encryption - RSA] ---
        # Implementation: Loading RSA private key
        with open(os.path.join(self.key_dir, 'private_key.pem'), 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # --- [REQUIREMENT: Encryption - RSA] ---
        # Implementation: Loading RSA public key
        with open(os.path.join(self.key_dir, 'public_key.pem'), 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def sign_data(self, data_string):
        """Signs a string using the Admin's private key."""
        # --- [REQUIREMENT: Digital Signature using Hash] ---
        # Implementation: RSA-PSS Signing using SHA256
        signature = self.private_key.sign(
            data_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # --- [REQUIREMENT: Encoding - Base64] ---
        # Implementation: Binary-to-Text encoding for safe storage of signatures
        return base64.b64encode(signature).decode()

    def verify_signature(self, data_string, signature_b64):
        """Verifies signature using the Public key."""
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature,
                data_string.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verification Failed: {e}")
            return False
