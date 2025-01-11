
# Reference from https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/ and join different peces of code and modified them accordingly
import json # to read and write json files
from cryptography.hazmat.primitives.asymmetric import padding  # For RSA padding schemes
from cryptography.hazmat.primitives.hashes import SHA256  # For hashing (used in signature verification)
from cryptography.hazmat.primitives import serialization  # For loading RSA keys in PEM format

#Paillier Decryption function (already Discussed)
def decrypt(public_key, private_key, ciphertext):
    n = public_key["n"]
    n_squared = n * n
    lambda_n = private_key["lambda"]
    mu = private_key["mu"]

    c_lambda = pow(ciphertext, lambda_n, n_squared)
    Lc = (c_lambda - 1) // n
    plaintext = (Lc * mu) % n
    return plaintext

if __name__ == "__main__":
   # command line handling
    import sys
     # Ensure correct usage of the script
    if len(sys.argv) != 2:
        print("Usage: python decrypt.py <filename.enc>")
        sys.exit(1)

    # Load keys from json files
    with open("public_key_Paillier.json", "r") as pub_file:
        public_key = json.load(pub_file)
    with open("private_key_Paillier.json", "r") as priv_file:
        private_key = json.load(priv_file)
    with open("rsa_public_key.pem", "rb") as rsa_file:
        rsa_public_key = serialization.load_pem_public_key(rsa_file.read())

    # Read ciphertext and signature
    input_filename = sys.argv[1]
    with open(input_filename, "r") as infile:
        enc_data = json.load(infile)
        ciphertext = enc_data["ciphertext"] # Load ciphertext
        signature = bytes.fromhex(enc_data["signature"]) # Load signature (stored in hex format)

    # Verify signature
     # Ensure the ciphertext has not been tampered with by verifying its RSA signature
    ciphertext_bytes = str(ciphertext).encode() # Convert ciphertext to bytes
    try:
        rsa_public_key.verify(
            signature, # Digital signature to verify
            ciphertext_bytes, # Original ciphertext in bytes
             # Mask generation function with SHA256 and maximize salt length
            padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            SHA256()  # Hashing algorithm
        )
        print("Signature verified.")
    except Exception as e:
        print(f"Signature verification failed: {e}")
        sys.exit(1)

    # Decrypt the ciphertext
    plaintext = decrypt(public_key, private_key, ciphertext)

    # Save plaintext 
    #took reference from the moodle file "File Encryption Demo.pdf" and modified it accordingly.
    output_filename = input_filename.replace(".enc", "_decrypted.txt")
    with open(output_filename, "w") as outfile:
        outfile.write(str(plaintext))

    print(f"Decrypted plaintext saved to {output_filename}.")
