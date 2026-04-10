import hashlib
import base64
import os

from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# ------------------ Utility Functions ------------------

def pad(data, block_size):
    while len(data) % block_size != 0:
        data += b' '
    return data


# ------------------ Cryptographic Functions ------------------

def sha_hash(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).digest()


def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data, 8))


def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, 16))


def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def rsa_decrypt(data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)


# ------------------ RSA Key Generation ------------------

if not os.path.exists("rsa_private.pem"):
    key = RSA.generate(2048)
    with open("rsa_private.pem", "wb") as f:
        f.write(key.export_key())
    with open("rsa_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

with open("rsa_public.pem", "rb") as f:
    PUBLIC_KEY = RSA.import_key(f.read())

with open("rsa_private.pem", "rb") as f:
    PRIVATE_KEY = RSA.import_key(f.read())


# ------------------ Registration ------------------

def register(username, password):
    # Step 1: SHA hashing
    hashed = sha_hash(password)

    # Step 2: DES encryption
    des_key = b'8bytekey'
    des_encrypted = des_encrypt(hashed, des_key)

    # Step 3: AES encryption
    aes_key = get_random_bytes(16)
    aes_encrypted = aes_encrypt(des_encrypted, aes_key)

    # Step 4: RSA encrypt AES key
    rsa_encrypted_key = rsa_encrypt(aes_key, PUBLIC_KEY)

    # Store in file
    with open("users.txt", "a") as f:
        f.write(
            username + "|" +
            base64.b64encode(rsa_encrypted_key).decode() + "|" +
            base64.b64encode(aes_encrypted).decode() + "\n"
        )

    print("User registered successfully.")


# ------------------ Login ------------------

def login(username, password):
    hashed = sha_hash(password)
    des_key = b'8bytekey'

    with open("users.txt", "r") as f:
        for line in f:
            stored_user, enc_aes_key, enc_password = line.strip().split("|")

            if stored_user == username:
                # Decrypt AES key using RSA
                aes_key = rsa_decrypt(
                    base64.b64decode(enc_aes_key),
                    PRIVATE_KEY
                )

                # Encrypt entered password using same steps
                des_encrypted = des_encrypt(hashed, des_key)
                aes_encrypted = aes_encrypt(des_encrypted, aes_key)

                if base64.b64encode(aes_encrypted).decode() == enc_password:
                    return True

    return False


# ------------------ Main Program ------------------

def main():
    print("1. Register")
    print("2. Login")
    choice = input("Choose option: ")

    username = input("Username: ")
    password = input("Password: ")

    if choice == "1":
        register(username, password)
    elif choice == "2":
        if login(username, password):
            print("Login successful.")
        else:
            print("Invalid username or password.")
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
