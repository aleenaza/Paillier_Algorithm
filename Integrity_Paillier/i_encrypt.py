
# Reference from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/ and join different peces of code and modified them accordingly

import random  # For generating random values
import json  # To handle public key and ciphertext storage
from sympy import gcd  # For computing the greatest common divisor
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization

# Paillier Encryption Function (already explained)
def encrypt(public_key, plaintext):
    n = public_key["n"]
    g = public_key["g"]
    n_squared = n * n

    if plaintext >= n:
        raise ValueError("Plaintext is too large to encrypt.")

    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    c = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared
    return c

if __name__ == "__main__":
    # Command Line Handling
    import sys
    # Ensure Correct Script
    if len(sys.argv) != 2:
        print("Usage: python encrypt.py <filename.txt>")
        sys.exit(1)

    # Load Paillier public key
    with open("public_key_Paillier.json", "r") as pub_file:
        public_key = json.load(pub_file)

    # Load RSA private key to sign the ciphertext for integrity and authentication.
    with open("rsa_private_key.pem", "rb") as rsa_file:
        rsa_private_key = serialization.load_pem_private_key(
            rsa_file.read(), password=None  # Load the private key (unencrypted)
        )

    # Read plaintext from file
    input_filename = sys.argv[1]
    with open(input_filename, "r") as infile:  # Read plaintext as an integer
        plaintext = int(infile.read().strip())

    # Encrypt the plaintext
    ciphertext = encrypt(public_key, plaintext)

    # Sign the ciphertext
    ciphertext_bytes = str(ciphertext).encode() # Convert ciphertext to bytes
    signature = rsa_private_key.sign(
        ciphertext_bytes,  # Original ciphertext in bytes
         # Mask generation function with SHA256 and maximize salt length
        padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        SHA256() # Hashing algorithm
    )

    # Save ciphertext and signature
    # Save plaintext 
    #took reference from the moodle file "File Encryption Demo.pdf" and https://www.geeksforgeeks.org/file-handling-python/ , and modified it accordingly.
    output_filename = input_filename.replace(".txt", ".enc")
    with open(output_filename, "w") as outfile:
        json.dump({"ciphertext": ciphertext, "signature": signature.hex()}, outfile)

    print(f"Ciphertext and signature saved to {output_filename}.")
