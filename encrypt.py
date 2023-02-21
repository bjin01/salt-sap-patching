import sys
from cryptography.fernet import Fernet
 
# we will be encrypting the below string.
if sys.argv:
    pwd = sys.argv[1]
 
# generate a key for encryption and decryption
# You can use fernet to generate
# the key or use random key generator
 
key = Fernet.generate_key()
print("Randomly generated key! Keep it safely!: \n{}".format(key.decode()))
# Instance the Fernet class with the key
fernet = Fernet(key)
 
# then use the Fernet class instance
# to encrypt the string string must
# be encoded to byte string before encryption
encrypted_pwd = fernet.encrypt(pwd.encode())
 
print("\nSave this encrypted password in your configuration file.\n{} ".format(encrypted_pwd.decode()))
 
