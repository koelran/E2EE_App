import sys
import os

# Add the parent directory (m16) to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import base64
import json

import rsaKeyManager
from client_init import load_server_public_key



def chunk_json_data(data):
    server_public_key = load_server_public_key()
  #  server_public_key = rsaKeyManager.load_public_key_from_keys_file("server_keys.txt")
    encrypted_chunks = rsaKeyManager.encrypt_in_chunks(json.dumps(data).encode(), server_public_key)
    serialized_chunks = [base64.b64encode(chunk).decode('utf-8') for chunk in encrypted_chunks]
    return serialized_chunks

