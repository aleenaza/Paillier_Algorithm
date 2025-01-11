#For this code, I took reference from https://www.youtube.com/watch?v=Yerhc9B2zjQ and https://github.com/mikeivanov/paillier/blob/master/paillier/paillier.py and then modified accordingly

import random  # For generating random values
import json  # To handle public key and ciphertext storage
from sympy import gcd  # For computing the greatest common divisor
import os  # For handling file paths and extensions


# Function to encrypt plaintext
def encrypt(public_key, plaintext):

    # Extracting n and g from plaintext
    n = public_key["n"]
    g = public_key["g"]
    # calculating n square
    n_squared = n * n
    
    # Ensure plaintext is within valid range
    if plaintext >= n:
        raise ValueError("Plaintext is too large to encrypt. Ensure it is less than n.")

 # Generate random r such that 0 < r < n and gcd(r, n) = 1
 # I took the reference from https://www.w3schools.com/python/numpy/numpy_random.asp and modified the code accordingly
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    # formula of encryption: c = (g^plaintext * r^n) mod n^2
    # Referenced from https://www.youtube.com/watch?v=Yerhc9B2zjQ

    c = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared
    return c


if __name__ == "__main__":
   
   # Ensure correct command-line usage
   # took reference from https://www.geeksforgeeks.org/how-to-use-sys-argv-in-python/
    import sys
    if len(sys.argv) != 2:
        print("Usage: python encrypt.py <filename.txt>")
        sys.exit(1)

    # Load the public key
    #took reference from the moodle file "File Encryption Demo.pdf" and https://www.geeksforgeeks.org/reading-and-writing-json-to-a-file-in-python/
    with open("public_key.json", "r") as pub_file:
        public_key = json.load(pub_file)

    # Read plaintext from file
    input_filename = sys.argv[1] # Input file provided via command-line

   
    with open(input_filename, "r") as infile:
         # As plaintext is single non-numeric data stored in file
    # took reference from https://deepnote.com/app/evan-mcneill/Untitled-Python-Project-3c478b5a-ca98-4c56-ad72-27b573a2375d for strip()
        plaintext = int(infile.read().strip())

    # Encrypt the plaintext
    ciphertext = encrypt(public_key, plaintext)

    
  
    # Save the ciphertext to an .enc file
    #took reference from the moodle file "File Encryption Demo.pdf" and modified it accordingly.
    output_filename = os.path.splitext(input_filename)[0] + ".enc"
    with open(output_filename, "w") as outfile:
       
        json.dump({"ciphertext": ciphertext}, outfile)

    print(f"Results saved to '{output_filename}'.")
