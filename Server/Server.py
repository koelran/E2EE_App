
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
from clientsDB import add_client, load_database, save_database
import rsaKeyManager
import random
import string


# Server details
HOST = '127.0.0.1'  # Localhost for testing
PORT = 65432        # Port to listen on

# Dictionary to keep track of connected clients
client_sockets = {}
# Load server database
client_database = load_database()
server_private_key, server_public_key = rsaKeyManager.get_or_generate_keys("server_keys.txt")  # RSA keys for the server
running = True  # Global flag to control server state

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
    try:
        # Generate a random PWD
        pwd = ''.join(random.choices(string.digits, k=6))
        print(f"Generated PWD")

        # Send the PWD directly to the client
        recv_socket.sendall(pwd.encode('utf-8'))
        print("PWD sent to the client via secure channel.")
        return pwd
    except Exception as e:
        print(f"Error in send_by_secure_channel: {e}")

def handle_initialization(data, recv_socket,send_socket, pwd):
    try:
        # Step 1: Receive and validate the PWD
        password = data.get("MyPWD")
        if not password:
            print("Initialization failed: Missing PWD.")
            return

        if password != pwd:
            print("Initialization failed: Invalid PWD.")
            return

        # Step 2: Extract client's phone number and public key
        phone_number = data.get("MyPhoneNumber")
        if not phone_number:
            print("Initialization failed: Missing phone number.")
            return

        #save the client socket to recive messages in the future
        client_sockets[phone_number] = send_socket


        public_key_pem = data.get("MyPublicKey")
        if not public_key_pem:
            print("Initialization failed: Missing public key.")
            return

        # Step 3: Add client to the server database
        add_client(phone_number, public_key_pem, "online", database=client_database)
        save_database(client_database)

        # Step 4: Send success response to the client
        send_ack(recv_socket,public_key_pem)
      #  recv_socket.sendall(b"Initialization successful")
        print(f"Client {phone_number} initialized successfully.")
    except Exception as e:
        print(f"Initialization error: {e}")

def handle_client_offline(data, recv_socket):
    data = rsaKeyManager.chunk_decrypt(data, server_private_key)
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

def handle_client_online(data, recv_socket):
    data = rsaKeyManager.chunk_decrypt(data, server_private_key)
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
        print(f"Client {phone_number} marked as online.")
        stored_msg_lst = client_database[phone_number]["messages"]
        if len(stored_msg_lst) > 0:
            for encrypted_msg in stored_msg_lst:
                transfer_message_between_clients(encrypted_msg, phone_number)
            client_database[phone_number]["messages"] = []
            save_database(client_database)
        return
    else:
        print(f"Error: Client {phone_number} not found in database.")
        return

def send_client_public_key(data, des_pnum, recv_socket):
    #decrypte data
    data = rsaKeyManager.chunk_decrypt(data, server_private_key)
    my_phone_number = data.get("MyPhoneNumber")
    my_public_key_pem = client_database[my_phone_number]["public_key"]
    my_public_key = serialization.load_pem_public_key(
        my_public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    if des_pnum not in client_database:
        des_public_key = None
    else:
        des_public_key = client_database[des_pnum]["public_key"]

    online_signature = rsaKeyManager.sign_message(my_phone_number, server_private_key)


    data_for_encryption = {
        "DestPublicKey": des_public_key,
        "signature": online_signature.hex()
    }
    encrypted_data = rsaKeyManager.chunk_encrypt(data_for_encryption, my_public_key)
    message = {
        "Command": 2,
        "DestPhoneNumber": des_pnum,
        "encrypted_chunks": encrypted_data
    }
    serialized_message = json.dumps(message)
    recv_socket.sendall(serialized_message.encode('utf-8'))
    print(f"public key of: {des_pnum}, sent to: {my_phone_number}")

def transfer_message_between_clients(message,des_pnum):
    try:
        des_socket = client_sockets[des_pnum]
    except Exception as e:
        print(f"exeption: {e}")
    if des_pnum in client_database:
        if client_database[des_pnum]["status"] == "offline":
            client_database[des_pnum]["messages"].append(message)
            save_database(client_database)
        else:
            message = {
                "Command": 1,
                "DestPhoneNumber": des_pnum,
                "encrypted_chunks": message
            }
            serialized_message = json.dumps(message)
            des_socket.sendall(serialized_message.encode('utf-8'))
            print(f"message transferred to: {des_pnum}")
    else:
        print(f"Error: Client {des_pnum} not found in database.")
        return

def handle_client(recv_socket, send_socket, addr):
    """Handle individual client connections."""
    print(f"Client connected from {addr}")
    try:
        # Step 1: Send PWD to client
        pwd = send_by_secure_channel(recv_socket)
        # Step 2: Receive initialization data before entering the main loop
        raw_data = recv_socket.recv(2048).decode('utf-8')
        if raw_data:
            try:
                public_data = json.loads(raw_data)
                decrypted_data = rsaKeyManager.chunk_decrypt(public_data.get("encrypted_chunks") , server_private_key)
                if public_data.get("Command") == 3:
                    handle_initialization(decrypted_data, recv_socket,send_socket,pwd)
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
                public_data = json.loads(raw_data)
                encrypted_data = public_data.get("encrypted_chunks")
                command = public_data.get("Command")
                # Handle commands using match-case
                match command:
                    case 1:
                        send_client_public_key(encrypted_data, public_data["DestPhoneNumber"], recv_socket)
                    case 2:
                        transfer_message_between_clients(encrypted_data, public_data["DestPhoneNumber"])
                    case 4:
                        handle_client_online(encrypted_data, recv_socket)
                    case 5:
                        handle_client_offline(encrypted_data, recv_socket)
                    case _:
                        print(f"Unknown command received: {command}")
            except Exception as e:
                print(f"Error processing client data: {e}")

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        # Mark the client as offline
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



