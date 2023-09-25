#!/usr/bin/env python3
import subprocess
import os
import re
import yaml
import string
from cryptography.fernet import Fernet

# Path to the YAML definition file
definition_file_path = "/etc/encryption_definition.yaml"
# Path to the encryption key file
encryption_key_file_path = "/etc/encryption_key.key"

def load_definition():
    try:
        with open(definition_file_path, "r") as file:
            definition = yaml.safe_load(file)
        print("got definition file {}".format(definition))
        return definition
    except Exception as e:
        print(f"Error loading definition file: {e}")
        return []

def load_key(key_file_path):
    try:
        with open(key_file_path, "rb") as file:
            key = file.read()
        return key
    except Exception as e:
        print(f"Error loading key from file '{key_file_path}': {e}")
        return None

def encrypt_value(value, key):
    fernet = Fernet(key)

    # Encrypt the value
    encrypted_value = fernet.encrypt(value.encode())
    print("func encrypt_value {}".format(encrypt_value))

    return encrypted_value

def process_file(file_path, encrypt_keys, encryption_key):
    
    try:
        # Read the content of the file
        with open(file_path, 'r') as file:
            file_lines = file.readlines()

        # Encrypt specified keys for a git push or decrypt for a git pull
        updated_lines = []
        
        for key in encrypt_keys:
            for line in file_lines:
                pattern = r'^\s*' + re.escape(key) + r':\s*([^\s]+)\s*$'
                match = re.search(pattern, line)
                if match:
                    value_to_encrypt = match.group(1)
                    new_line = line.replace(value_to_encrypt, encrypt_value(value_to_encrypt, encryption_key).decode())
                    updated_lines.append(new_line)
                else:
                    updated_lines.append(line)
            
        # Write the updated content back to the file
        with open(file_path, 'w') as file:
            file.writelines(updated_lines)

    except Exception as e:
        print(f"Error processing file '{file_path}': {e}")

def main():
    definition = load_definition()
    if not definition:
        return

    # Load encryption and decryption keys
    encryption_key = load_key(encryption_key_file_path)
    

    if not encryption_key:
        return

    for item in definition:
        file_path = item.get("file_path", "")
        encrypt_keys = item.get("encrypt_keys", [])

        if os.path.isfile(file_path):
            process_file(file_path, encrypt_keys, encryption_key)
        else:
            print(f"File '{file_path}' does not exist.")

if __name__ == "__main__":
    main()
