import sys
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Add the parent directory (m16) to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import socket
import threading
import rsaKeyManager
import client_init

# Server details
HOST = '127.0.0.1'  # Server IP address (localhost for testing)
PORT = 65432        # Server port

# Global variable to signal thread termination
running = True
phone_number = None
private_key, public_key = rsaKeyManager.generate_rsa_keys()
rec_DB = {}

def receive_ack(recv_socket, client_private_key, server_public_key):
    try:
        # Step 1: Receive the encrypted acknowledgment
        raw_data = recv_socket.recv(4096)
        decrypted_message = rsaKeyManager.decrypt_msg_chunked(raw_data,client_private_key)
        # Parse the decrypted JSON message
        ack_data = json.loads(decrypted_message)
        # Step 4: Validate the signature
        command = str(ack_data["Command"])
        signature = bytes.fromhex(ack_data["signature"])
        is_valid = rsaKeyManager.verify_signature(command, signature, server_public_key)

        return is_valid
    except Exception as e:
        print(f"Error receiving acknowledgment: {e}")

def initial_setup(request_socket):
    global phone_number
    print("Performing initial setup...")
    #recive pwd via one time secure channel
    PWD = request_socket.recv(1024).decode('utf-8')
    if not PWD:
        raise Exception("Failed to receive PWD from server.")
    print(f"Received PWD from server: {PWD}")

    serialized_public_key = rsaKeyManager.get_serialized_public_key(public_key)
    print("Generated and saved RSA keys.")
    phone_number = input("Enter your phone number (6 digits): ")

    server_public_key = client_init.load_server_public_key()
    data_for_encryption = {
        "MyPhoneNumber": phone_number,
        "MyPublicKey": serialized_public_key,
        "MyPWD": PWD
    }
    encrypted_data = rsaKeyManager.chunk_encrypt(data_for_encryption, server_public_key)
    message = {
        "Command": 3,
        "DestPhoneNumber": 000000,
        "encrypted_chunks": encrypted_data
    }
    serialized_message = json.dumps(message)
    request_socket.sendall(serialized_message.encode('utf-8'))
    response = receive_ack(request_socket,private_key, server_public_key)
    if response:
        print("initializetion acknoleged by the server")
    else:
        print("initializetion NOT acknoleged by the server")

# Function to receive messages from the server
def receive_messages(general_socket, request_socket):
    global running
    while running:
        try:
            raw_data = general_socket.recv(4096).decode('utf-8')
            public_data = json.loads(raw_data)
            encrypted_data = public_data.get("encrypted_chunks")
            decrypted_data = rsaKeyManager.chunk_decrypt(encrypted_data, private_key)
            src_pnum = decrypted_data["SourcePhoneNumber"]
            rec_public_key = get_rec_public_key(request_socket, src_pnum)

            command = public_data.get("Command")
            if command == 1:
                decrypted_signature = bytes.fromhex(decrypted_data.get('signature'))
                is_valid = rsaKeyManager.verify_signature(phone_number, decrypted_signature, rec_public_key)
                if not is_valid:
                    print(f"cant verify {phone_number} message")
                else:
                    if decrypted_data["Command"] == 0:
                        message = decrypted_data["Message"]
                        # Overwrite with a new message without adding a newline
                        print(f"\nmessage from, {src_pnum} : {message}")
                        send_message_or_ack(request_socket, rec_public_key, src_pnum, "", 1)
                    elif decrypted_data["Command"] == 1:
                        print(f"\nclient, {src_pnum} recived message")

        except Exception as e:
            if running:  # Ignore exceptions after the program stops
                print(f"Error receiving message: {e}")
            break

def handle_offline_online(request_socket):
    global phone_number
    try:
        # Going offline
        online_signature = rsaKeyManager.sign_message(phone_number, private_key)
        server_public_key = client_init.load_server_public_key()

        # Send offline request
        data_for_encryption = {
            "MyPhoneNumber": phone_number,
            "signature": online_signature.hex()
        }
        encrypted_data = rsaKeyManager.chunk_encrypt(data_for_encryption, server_public_key)
        message = {
            "Command": 5,
            "DestPhoneNumber": 000000,
            "encrypted_chunks": encrypted_data
        }
        serialized_message = json.dumps(message)
        request_socket.sendall(serialized_message.encode('utf-8'))
        # Wait for server response
        response = receive_ack(request_socket,private_key, server_public_key)
        if response:
            print("server akcnowleged offline")

        # Wait for the user to come back online
        msg = input("You are offline - type ONLINE to get back online: ")
        while msg != 'ONLINE':
            msg = input("You are offline - type ONLINE to get back online: ")
        online_signature = rsaKeyManager.sign_message(phone_number, private_key)
        # Send online request
        data_for_encryption = {
            "MyPhoneNumber": phone_number,
            "signature": online_signature.hex()
        }
        encrypted_data = rsaKeyManager.chunk_encrypt(data_for_encryption, server_public_key)
        message = {
            "Command": 4,
            "DestPhoneNumber": 000000,
            "encrypted_chunks": encrypted_data
        }
        serialized_message = json.dumps(message)
        request_socket.sendall(serialized_message.encode('utf-8'))
        print("you are back online")

    except Exception as e:
        print(f"Error during offline/online handling: {e}")

def get_rec_public_key(request_socket, rec_pnum):
    if rec_pnum in rec_DB:
        return rec_DB[rec_pnum]

    online_signature = rsaKeyManager.sign_message(phone_number, private_key)
    server_public_key = client_init.load_server_public_key()
    data_for_encryption = {
        "MyPhoneNumber": phone_number,
        "signature": online_signature.hex()
    }
    encrypted_data = rsaKeyManager.chunk_encrypt(data_for_encryption, server_public_key)
    message = {
        "Command": 1,
        "DestPhoneNumber": rec_pnum,
        "encrypted_chunks": encrypted_data
    }
    serialized_message = json.dumps(message)
    request_socket.sendall(serialized_message.encode('utf-8'))

    raw_data = request_socket.recv(4096).decode('utf-8')
    public_data = json.loads(raw_data)
    decrypted_data = rsaKeyManager.chunk_decrypt(public_data.get("encrypted_chunks"), private_key)
    command = public_data.get("Command")
    if command == 2:
        decrypted_signature = bytes.fromhex(decrypted_data.get('signature'))
        is_valid = rsaKeyManager.verify_signature(phone_number, decrypted_signature, server_public_key)
        if not is_valid:
            print(f"cant verify {phone_number} message")
        else:
            des_public_key_pem = decrypted_data["DestPublicKey"]
            dest_public_key = serialization.load_pem_public_key(
                des_public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            rec_DB[rec_pnum] = dest_public_key
            return dest_public_key


def send_message_or_ack(request_socket, rec_public_key, rec_pnum, message, command):
    online_signature = rsaKeyManager.sign_message(rec_pnum, private_key)
    data_for_encryption = {
        "Command": command,
        "SourcePhoneNumber": phone_number,
        "Message": message,
        "signature": online_signature.hex()
    }
    encrypted_data = rsaKeyManager.chunk_encrypt(data_for_encryption, rec_public_key)
    message = {
        "Command": 2,
        "DestPhoneNumber": rec_pnum,
        "encrypted_chunks": encrypted_data
    }
    serialized_message = json.dumps(message)
    request_socket.sendall(serialized_message.encode('utf-8'))

# Function to send messages to the server
def send_messages(request_socket):
    global running
    try:
        print("\n---type 'QUIT' to go offline---\n")
        while running:
            rec_pnum = input("Enter recipients phone number : ")
            if rec_pnum.upper() == 'QUIT':
                handle_offline_online(request_socket)
                continue

            rec_public_key = get_rec_public_key(request_socket, rec_pnum)

            message = input(f"Enter your message for {rec_pnum}: ")
            send_message_or_ack(request_socket, rec_public_key, rec_pnum, message, 0)
    except Exception as e:
        print(f"Error during message sending: {e}")
    finally:
        request_socket.close()



# Main function
def connect_to_server():
    global running
    # Create two sockets
    general_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # For receiving updates
    request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # For sending requests

    # Connect both sockets to the server
    general_socket.connect((HOST, PORT))
    request_socket.connect((HOST, PORT))

    # Perform initial setup using the request socket
    initial_setup(request_socket)

    # Start a thread to handle receiving messages
    receive_thread = threading.Thread(target=receive_messages, args=(general_socket,request_socket))
    receive_thread.start()

    # Handle sending messages in the main thread
    send_messages(request_socket)

    # Wait for the receive thread to finish
    running = False  # Ensure thread terminates
    receive_thread.join()

if __name__ == "__main__":
    connect_to_server()
