#!/usr/bin/env python3
import subprocess
import os
import re
import yaml
import string
from cryptography.fernet import Fernet

# Path to the YAML definition file
definition_file_path = "/etc/encryption_definition.yaml"

# Path to the decryption key file
decryption_key_file_path = "/etc/encryption_key.key"

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

def decrypt_value(encrypted_value, key):
    print("func key {}".format(key))
    print("func encrypted_value {}".format(encrypted_value))
    fernet = Fernet(key)

    # Decrypt the value
    decrypted_value = fernet.decrypt(encrypted_value).decode()
    print("func decrypted_value {}".format(decrypted_value))

    return decrypted_value

def process_file(file_path, decrypt_keys, decryption_key):
    print("encryption_key {}".format(decryption_key.decode()))
    print("decrypt_keys {}".format(decrypt_keys))
    try:
        # Read the content of the file
        with open(file_path, 'r') as file:
            file_lines = file.readlines()

        # Encrypt specified keys for a git push or decrypt for a git pull
        updated_lines = []
        
        for key in decrypt_keys:
            for line in file_lines:
                pattern = r'^\s*' + re.escape(key) + r':\s*([^\s]+)\s*$'
                match = re.search(pattern, line)
                print("match in decrypt {}".format(match))
                if match:
                    value_to_decrypt = match.group(1)
                    #print("value_to_decrypt {}".format(value_to_decrypt))
                    new_line = line.replace(value_to_decrypt, decrypt_value(value_to_decrypt.encode(), decryption_key))
                    print("new_line in decrypt {}".format(new_line))
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

    decryption_key = load_key(decryption_key_file_path)

    if not decryption_key:
        return

    for item in definition:
        file_path = item.get("file_path", "")
        decrypt_keys = item.get("decrypt_keys", [])

        if os.path.isfile(file_path):
            process_file(file_path, decrypt_keys, decryption_key)
        else:
            print(f"File '{file_path}' does not exist.")

if __name__ == "__main__":
    main()
