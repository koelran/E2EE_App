import os
import sys
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from rsaKeyManager import *


def load_server_public_key():
    """
    Loads the server's public key and returns it as a cryptography public key object.

    Returns:
        public_key: The server's public key as a cryptography public key object.
    """
    server_public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6RhJqynywbQ/BUzXV0SB
OJXsdJuhRdDxeOPCErnUdj478J/Rut0vjRB9Mn4W0JLjdc0yWuq3a3Qn0ZVryNaw
9kMJAaQZR1iwqy8IVPzQg/orC5sg2qMi+Ax6K+CiAREh/HMazbOQqF6t9+dHxlku
ark39Ymxt8ZeJEesjg4fnYxvy5SvVDhhpLf/ao7Evrfgnfh54f1go7x1nvVFzF3A
xYSiBWjuv7OUas1QTMnskSvZAlq1iHvC3Poy8XJjcJXOeKMW8fFqe22ptsa1mGMl
/vIm+w+CL/ZxIsD6ma1qUJJ+2OCEti5K8MsBqH8+w7e1dXZDHx9UC09AxOijNqFv
4QIDAQAB
-----END PUBLIC KEY-----"""

    # Load the public key
    public_key = serialization.load_pem_public_key(
        server_public_key_pem,
        backend=default_backend()
    )

    return public_key


def retrieve_phone_number(file_name):
    """
    Retrieves the first phone number from the given file.

    Args:
        file_name (str): The name of the file to read the phone number from.

    Returns:
        str: The phone number found in the file.
    """
    with open(file_name, "r") as file:
        for line in file:
            if line.startswith("# Phone Number:"):
                # Extract the phone number from the line
                return line.replace("# Phone Number:", "").strip()
    return None  # Return None if no phone number is found


def client_init():
    file_name = "client_keys.txt"
    phone_number = retrieve_phone_number(file_name)
    print(f"phone_number: {phone_number}")
    private_key, public_key = get_or_generate_keys(file_name)
    server_public_key = load_server_public_key()
    signature = sign_message(phone_number, private_key)
    data = {
        "Command": 4,
        "MyPhoneNumber": phone_number,
        "Signature": signature.hex()  # Convert signature to a hex string for easy storage
    }
    combined_data = json.dumps(data)
    encrypted_chunks = encrypt_in_chunks(combined_data.encode(), server_public_key)
    # Assuming message is a list of encrypted chunks
    message_bytes = b''.join(encrypted_chunks)  # Join all chunks into one bytes object
    # Encode the concatenated message to Base64 and send it
    message = base64.b64encode(message_bytes).decode('utf-8').encode('utf-8')
    return message


