
import sys
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
# Add the parent directory (m16) to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import socket
import threading
import json
import base64
from clientsDB import add_client, update_client_status, update_client_messages, load_database, save_database
import rsaKeyManager
import random
import string
pwd = None

# Server details
HOST = '127.0.0.1'  # Localhost for testing
PORT = 65432        # Port to listen on

# Dictionary to keep track of connected clients
clients = {}
# Load server database
client_database = load_database()
server_private_key, server_public_key = rsaKeyManager.get_or_generate_keys("server_keys.txt")  # RSA keys for the server
running = True  # Global flag to control server state
pwd = None

def send_ack(send_socket , client_public_key_pem):
    try:
        client_public_key = serialization.load_pem_public_key(
        client_public_key_pem.encode('utf-8'),
        backend=default_backend()
        )
        # Step 1: Create the acknowledgment data
        command = 3
        signature = rsaKeyManager.sign_message(str(command), server_private_key)
        ack_data = {
            "Command": 3,
            "signature": signature.hex()
        }
        # Step 4: Encrypt the serialized JSON using the client's public key
        encrypted_ack = rsaKeyManager.encrypt_msg_chunked(ack_data, client_public_key)

        # Step 5: Send the encrypted acknowledgment
        send_socket.sendall(encrypted_ack)
        print("Secure acknowledgment sent to client.")
    except Exception as e:
        print(f"Error sending acknowledgment: {e}")


def send_by_secure_channel(recv_socket):
    """Send the PWD securely to the client before entering the main loop."""
    global pwd
    try:
        # Generate a random PWD
        pwd = ''.join(random.choices(string.digits, k=6))
        print(f"Generated PWD")

        # Send the PWD directly to the client
        recv_socket.sendall(pwd.encode('utf-8'))
        print("PWD sent to the client via secure channel.")
    except Exception as e:
        print(f"Error in send_by_secure_channel: {e}")


def handle_initialization(data, recv_socket):
    """Handle the client initialization process, including password reception and validation."""
    global pwd
    try:
        # Step 1: Receive and validate the PWD
        password = data.get("MyPWD")
        if not password:
            print("Initialization failed: Missing PWD.")
            return

        if password != pwd:
            print("Initialization failed: Invalid PWD.")
            return

        # Clear the PWD after validation for security
        pwd = None

        # Step 2: Extract client's phone number and public key
        phone_number = data.get("MyPhoneNumber")
        if not phone_number:
            print("Initialization failed: Missing phone number.")
            return

        public_key_pem = data.get("MyPublicKey")
        if not public_key_pem:
            print("Initialization failed: Missing public key.")
            return

        # Step 3: Add client to the server database
        add_client(phone_number, public_key_pem, "online", "", "", database=client_database)
        save_database(client_database)

        # Step 4: Send success response to the client
        send_ack(recv_socket,public_key_pem)
      #  recv_socket.sendall(b"Initialization successful")
        print(f"Client {phone_number} initialized successfully.")
    except Exception as e:
        print(f"Initialization error: {e}")

def handle_offline(data, recv_socket):
    phone_number = data.get("MyPhoneNumber")
    #validate signature
    client_public_key_pem = client_database[phone_number]["public_key"]
    client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))
    decrypted_signature = bytes.fromhex(data.get('signature'))
    is_valid = rsaKeyManager.verify_signature(str(phone_number), decrypted_signature, client_public_key)
    if not is_valid:
        print(f"cant verify {phone_number} message")
        return

    #change status in DB
    if phone_number in client_database:
        client_database[phone_number]["status"] = "offline"
        save_database(client_database)
        send_ack(recv_socket,client_public_key_pem)
        #recv_socket.sendall(b"User status updated to offline")
        print(f"Client {phone_number} marked as offline.")
        return
    else:
        #client_socket.sendall(b"Error: Client not found in database")
        print(f"Error: Client {phone_number} not found in database.")
        return

def handle_online(data, recv_socket):
    phone_number = data.get("MyPhoneNumber")
    # validate signature
    client_public_key_pem = client_database[phone_number]["public_key"]
    client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))
    decrypted_signature = bytes.fromhex(data.get('signature'))
    is_valid = rsaKeyManager.verify_signature(str(phone_number), decrypted_signature, client_public_key)
    if not is_valid:
        print(f"cant verify {phone_number} message")
        return

    if phone_number in client_database:
        client_database[phone_number]["status"] = "online"
        save_database(client_database)
        send_ack(recv_socket,client_public_key_pem)
        print(f"Client {phone_number} marked as online.")
        return
    else:
        print(f"Error: Client {phone_number} not found in database.")
        return


"""def handle_message(data):
    dest_phone_number = data["DestPhoneNumber"]
    source_phone_number = data["SourcePhoneNumber"]
    message = data["Message"]

    # Check if destination client exists in the database
    if dest_phone_number in server_database:
        recipient_data = server_database[dest_phone_number]
        if recipient_data["status"] == "online":
            # Forward the message
            recipient_socket = clients.get(dest_phone_number)
            if recipient_socket:
                recipient_socket.sendall(f"Message from {source_phone_number}: {message}".encode('utf-8'))
            print(f"Forwarding message from {source_phone_number} to {dest_phone_number}")
        else:
            # Store the message offline
            update_client_messages(dest_phone_number, message1=message, message2="")
            save_database(server_database)
            print(f"Storing message for offline client {dest_phone_number}")
    else:
        print(f"Client {dest_phone_number} not found in the database.")"""

def handle_client(recv_socket, send_socket, addr):
    """Handle individual client connections."""
    print(f"Client connected from {addr}")
    try:
        # Step 1: Send PWD to client
        send_by_secure_channel(recv_socket)
        # Step 2: Receive initialization data before entering the main loop
        raw_data = recv_socket.recv(2048).decode('utf-8')
        if raw_data:
            try:

                # Decrypt the received encrypted chunks
                decrypted_message = rsaKeyManager.decrypt_msg_chunked(raw_data,server_private_key)
                # Parse the decrypted JSON message
                data = json.loads(decrypted_message)
                # Handle initialization if the command is 3
                if data.get("Command") == 3:
                    handle_initialization(data, recv_socket)
                else:
                    print("Expected initialization command (3), but received a different command.")
                    return  # Disconnect the client if initialization is invalid
            except Exception as e:
                print(f"Error processing initialization data: {e}")
                return  # Disconnect the client if initialization fails


        while running:
            raw_data = recv_socket.recv(4096).decode('utf-8')
            if not raw_data:
                break
            try:
                decrypted_message = rsaKeyManager.decrypt_msg_chunked(raw_data,server_private_key)
                data = json.loads(decrypted_message)
                command = data.get("Command")
                # Handle commands using match-case
                match command:
                    case 4:
                        handle_online(data, recv_socket)
                    case 5:
                        handle_offline(data, recv_socket)
                    case _:
                        print(f"Unknown command received: {command}")
            except Exception as e:
                print(f"Error processing client data: {e}")

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        # Mark the client as offline
        for phone_number, client_data in client_database.items():
            if client_data.get("status") == "online":
                update_client_status(phone_number, "offline")
                save_database(client_database)
        recv_socket.close()
        send_socket.close()
        print(f"Client from {addr} disconnected.")

def start_server():
    """Start the server and initialize RSA keys."""
    global server_private_key, server_public_key
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server started, listening on {HOST}:{PORT}")

    # Initialize RSA keys
    print("Initializing server keys...")
    server_private_key, server_public_key = rsaKeyManager.get_or_generate_keys("server_keys.txt")
    print("Server keys initialized successfully.")

    try:
        while running:
            try:
                # Accept connections for both recv_socket and send_socket
                send_socket, addr_send = server_socket.accept()
                recv_socket, addr_recv = server_socket.accept()

                # Verify that both sockets come from the same client (same IP, different ports)
                if addr_recv[0] == addr_send[0]:
                    print(f"Two sockets established for client at {addr_recv[0]}")
                    thread = threading.Thread(target=handle_client, args=(recv_socket, send_socket, addr_recv))
                    thread.start()
                else:
                    print(f"Socket mismatch: {addr_recv[0]} and {addr_send[0]}")
                    recv_socket.close()
                    send_socket.close()
            except Exception as e:
                print(f"Error accepting client: {e}")
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        server_socket.close()
        print("Server stopped.")

if __name__ == "__main__":
    start_server()



