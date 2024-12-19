import os
import sys
from cryptography.hazmat.backends import default_backend

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from rsaKeyManager import *


def load_server_public_key():

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




