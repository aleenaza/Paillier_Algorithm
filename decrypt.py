
#For this code, I took reference from https://www.youtube.com/watch?v=Yerhc9B2zjQ and https://github.com/mikeivanov/paillier/blob/master/paillier/paillier.py and then modified accordingly
import json
import hmac
from hashlib import sha256

# Function to compute L(x) in Paillier decryption
def L(x, n):
    return (x - 1) // n

# Function to decrypt ciphertext
#  The decryption formula is derived from the Paillier cryptosystem:
 #     plaintext = L(c^lambda mod n^2) * mu mod n
def decrypt(public_key, private_key, ciphertext):
    n = public_key["n"]
    n_squared = n * n
    lambda_n = private_key["lambda"]
    mu = private_key["mu"]

   # Perform decryption steps
    c_lambda = pow(ciphertext, lambda_n, n_squared)  # Compute c^lambda mod n^2
    Lc = L(c_lambda, n)  # Compute L(c^lambda mod n^2)
    plaintext = (Lc * mu) % n  # Final decryption step
    return plaintext


if __name__ == "__main__":
   
    import sys
    if len(sys.argv) != 2:
        print("Usage: python decrypt.py <filename.enc>")
        sys.exit(1)

    # Load the keys
     # took reference from the moodle file "File Encryption Demo.pdf" and https://www.geeksforgeeks.org/reading-and-writing-json-to-a-file-in-python/
    with open("public_key.json", "r") as pub_file:
        public_key = json.load(pub_file)
    with open("private_key.json", "r") as priv_file:
        private_key = json.load(priv_file)

    # Read ciphertext from file
    input_filename = sys.argv[1]
    with open(input_filename, "r") as infile:
        enc_data = json.load(infile)
        ciphertext = enc_data["ciphertext"]
       

   

    # Decrypt the ciphertext
    plaintext = decrypt(public_key, private_key, ciphertext)

    # Save the plaintext to a new file
    #took reference from the moodle file "File Encryption Demo.pdf" and modified it accordingly.
    output_filename = input_filename.replace(".enc", "_decrypted.txt")
    with open(output_filename, "w") as outfile:
        outfile.write(str(plaintext))

    print(f"Decrypted plaintext saved to '{output_filename}'.")
