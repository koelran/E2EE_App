import base64
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.exceptions import InvalidSignature


def generate_rsa_keys():
    """Generate RSA public and private keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_keys_to_file(private_key, public_key, file_path="keys.txt"):
    """Save RSA keys to a file."""
    with open(file_path, "wb") as f:
        # Serialize and write the private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.write(private_key_pem)

        # Serialize and write the public key
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f.write(public_key_pem)

def load_public_key_from_keys_file(file_path="server_keys.txt"):
    """Extract and load the public key from a combined keys file."""
    try:
        with open(file_path, "rb") as f:
            # Read the file contents
            key_data = f.read()

            # Find and extract the public key section
            public_key_start = key_data.find(b"-----BEGIN PUBLIC KEY-----")
            public_key_end = key_data.find(b"-----END PUBLIC KEY-----") + len(b"-----END PUBLIC KEY-----")
            public_key_pem = key_data[public_key_start:public_key_end]

            # Deserialize the public key
            public_key = serialization.load_pem_public_key(public_key_pem)
            return public_key
    except FileNotFoundError:
        raise FileNotFoundError(f"The keys file '{file_path}' was not found.")
    except Exception as e:
        raise Exception(f"An error occurred while extracting the public key: {e}")


def load_keys_from_file(file_path="keys.txt"):
    """Load RSA keys from a file."""
    with open(file_path, "rb") as f:
        # Read the contents of the file
        key_data = f.read()

        # Split the file into private and public key sections
        private_key_start = key_data.find(b"-----BEGIN PRIVATE KEY-----")
        private_key_end = key_data.find(b"-----END PRIVATE KEY-----") + len(b"-----END PRIVATE KEY-----")
        public_key_start = key_data.find(b"-----BEGIN PUBLIC KEY-----")
        public_key_end = key_data.find(b"-----END PUBLIC KEY-----") + len(b"-----END PUBLIC KEY-----")

        private_key_pem = key_data[private_key_start:private_key_end]
        public_key_pem = key_data[public_key_start:public_key_end]

        # Deserialize private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        # Deserialize public key
        public_key = serialization.load_pem_public_key(public_key_pem)

        return private_key, public_key


def get_or_generate_keys(file_path="keys.txt"):
    """Get RSA keys from file if available, otherwise generate and save new ones."""
    if os.path.exists(file_path):
        print(f"File '{file_path}' found. Loading keys...")
        private_key, public_key = load_keys_from_file(file_path)
    else:
        print(f"File '{file_path}' not found. Generating new keys...")
        private_key, public_key = generate_rsa_keys()
        save_keys_to_file(private_key, public_key, file_path)
    return private_key, public_key

def get_serialized_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def encrypt_message(message, public_key):
    """Encrypt a message using the provided public key."""
    encrypted_message = public_key.encrypt(
        message.encode(),
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    """Decrypt a message using the provided private key."""
    decrypted_message = private_key.decrypt(
        encrypted_message,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()


def sign_message(message, private_key):
    """Sign a message using the private key."""
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(message, signature, public_key):
    """Verify a signature using the public key."""
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def encrypt_in_chunks(data, public_key, chunk_size=190):
    """Encrypt data in chunks using the public key."""
    encrypted_chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)
    return encrypted_chunks


def decrypt_in_chunks(encrypted_chunks, private_key):
    """Decrypt encrypted chunks using the private key."""
    decrypted_data = b""
    for chunk in encrypted_chunks:
        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_data += decrypted_chunk
    return decrypted_data

def chunk_encrypt(data_for_encryption, public_key):
    encrypted_chunks = encrypt_in_chunks(json.dumps(data_for_encryption).encode(), public_key)
    serialized_chunks = [base64.b64encode(chunk).decode('utf-8') for chunk in encrypted_chunks]
    return serialized_chunks

def chunk_decrypt(serialized_chunks, server_private_key):
    encrypted_chunks = [base64.b64decode(chunk) for chunk in serialized_chunks]
    decrypted_data = decrypt_in_chunks(encrypted_chunks, server_private_key)
    original_data = json.loads(decrypted_data.decode('utf-8'))
    return original_data

def encrypt_msg_chunked(data, rec_public_key):
    encrypted_chunks = encrypt_in_chunks(json.dumps(data).encode(), rec_public_key)
    serialized_chunks = [base64.b64encode(chunk).decode('utf-8') for chunk in encrypted_chunks]
    msg = json.dumps({"encrypted_chunks": serialized_chunks}).encode()
    return msg

def decrypt_msg_chunked(data,rec_private_key):
    encrypted_chunks = [base64.b64decode(chunk) for chunk in
                        json.loads(data).get("encrypted_chunks", [])]
    decrypted_message = decrypt_in_chunks(encrypted_chunks, rec_private_key).decode()
    return decrypted_message

