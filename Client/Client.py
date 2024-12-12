import sys
import os

# Add the parent directory (m16) to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import socket
import threading
import rsaKeyManager
import base64
from ClientTools import chunk_json_data
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
    encrypted_data = rsaKeyManager.chunk_encrypt(data_for_encryption,server_public_key)
    message = {
        "Command": 3,
        "DestPhoneNumber": 000000,
        "encrypted_chunks": encrypted_data
    }
    serialized_message = json.dumps(message)
    request_socket.sendall(serialized_message.encode('utf-8'))
    #message = rsaKeyManager.encrypt_msg_chunked(data, server_public_key)
    #request_socket.sendall(message)
    response = receive_ack(request_socket,private_key,server_public_key)
    if response:
        print("initializetion acknoleged by the server")
    else:
        print("initializetion NOT acknoleged by the server")

# Function to receive messages from the server
def receive_messages(general_socket):
    global running
    while running:
        try:
            message = general_socket.recv(1024).decode('utf-8')
            if message:  # Only display if there's an actual message
                print(f"\n{message}")
            else:
                # If no message, the server may have closed the connection
                print("\nConnection closed by the server.")
                break
        except Exception as e:
            if running:  # Ignore exceptions after the program stops
                print(f"Error receiving message: {e}")
            break

def handle_offline_online(request_socket):
    global phone_number
    try:
        # Going offline
        online_signature = rsaKeyManager.sign_message(phone_number , private_key)
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
        response = receive_ack(request_socket,private_key,server_public_key)
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
        is_valid = rsaKeyManager.verify_signature(rec_pnum, decrypted_signature, server_public_key)
        if not is_valid:
            print(f"cant verify {phone_number} message")
        des_public_key = decrypted_data["DestPublicKey"]
        rec_DB[rec_pnum] = des_public_key
        return des_public_key


def send_message_to_x(request_socket, rec_public_key, message):
    pass
# Function to send messages to the server
def send_messages(request_socket):
    global running
    try:
        print("\n---type 'QUIT' to go offline---\n")
        while running:
            rec_pnum = input("Enter phone number : ")
            if rec_pnum.upper() == 'QUIT':
                handle_offline_online(request_socket)
                continue

            rec_public_key = get_rec_public_key(request_socket,rec_pnum)

            message = input(f"Enter your message for {rec_pnum}: ")
            if message.upper() == 'QUIT':
                handle_offline_online(request_socket)
                continue
            else:
                send_message_to_x(request_socket,rec_public_key,message)


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
    receive_thread = threading.Thread(target=receive_messages, args=(general_socket,))
    receive_thread.start()

    # Handle sending messages in the main thread
    send_messages(request_socket)

    # Wait for the receive thread to finish
    running = False  # Ensure thread terminates
    receive_thread.join()

if __name__ == "__main__":
    connect_to_server()
