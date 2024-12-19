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


