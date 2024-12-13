import os
import sys
import json

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from rsaKeyManager import *

# Define the file where the database will be stored
DB_FILE = "client_database.json"

# Database structure: a dictionary where key is the phone number
client_database = {}


def load_database():
    """Load the database from the file if it exists."""
    try:
        with open(DB_FILE, 'r') as db_file:
            return json.load(db_file)
    except FileNotFoundError:
        # If the file doesn't exist, return an empty dictionary
        return {}


def save_database(database, file_path="client_database.json"):
    """Save the database to a file."""
    with open(file_path, 'w') as db_file:
        json.dump(database, db_file, indent=4)
    print(f"Database saved to {file_path}.")


def add_client(phone_number, public_key_pem, status, database=None):
    if database is None:
        raise ValueError("A valid database must be provided.")

    if phone_number in database:
        print(f"Client {phone_number} already exists.")
    else:
        # Ensure public_key_pem is stored as a string
        if isinstance(public_key_pem, bytes):
            public_key_pem = public_key_pem.decode('utf-8')

        # Add the client entry to the database
        database[phone_number] = {
            "public_key": public_key_pem,
            "status": status,
            "messages": []
        }
        print(f"Client {phone_number} added successfully to DB.")


def update_client_status(phone_number, status, ):
    """Update the status of an existing client."""
    if phone_number in client_database:
        client_database[phone_number]['status'] = status
        print(f"Client {phone_number} status updated to {status}.")
        save_database()
    else:
        print(f"Client {phone_number} not found.")


def update_client_messages(phone_number, message1, message2):
    """Update the messages of an existing client."""
    if phone_number in client_database:
        client_database[phone_number]['message1'] = message1
        client_database[phone_number]['message2'] = message2
        print(f"Messages for client {phone_number} updated.")
        save_database()
    else:
        print(f"Client {phone_number} not found.")


def view_client(phone_number):
    """View the details of a specific client."""
    if phone_number in client_database:
        client = client_database[phone_number]
        print(f"Client {phone_number}: {client}")
    else:
        print(f"Client {phone_number} not found.")


# Example usage:
if __name__ == "__main__":
    # Load the database from file (if exists)
  ''' client_database = load_database()

    server_private_key, server_public_key = get_or_generate_keys("server_keys.txt")

    # Adding a new client
    # add_client("1", public_key, "online", "Hello, Client 1", "Message 2 for Client 1")

    ## Updating client status
    # update_client_status("1", "offline")
    #
    ## Updating client messages
    # update_client_messages("1", "New message for Client 1", "Another new message for Client 1")
    #
    ## View a client's details
    # view_client("1")

    # Retrieve the public key from the JSON
    public_key_pem = client_database["1"]["public_key"]

    # Deserialize the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

    # Message to encrypt
    message = "This is a confidential message."

    encrypted_chunks = encrypt_in_chunks(message.encode(), public_key)
    decrypted_data = decrypt_in_chunks(encrypted_chunks, server_private_key)
    print(f"The message is: {decrypted_data.decode()}")'''