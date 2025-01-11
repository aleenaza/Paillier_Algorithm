#For this code, I took reference from https://www.youtube.com/watch?v=Yerhc9B2zjQ and https://github.com/mikeivanov/paillier/blob/master/paillier/paillier.py and then modified accordingly

import json
import sys

# Homomorphic scalar multiplication
def homomorphic_scalar(public_key, c, scalar):
    # formula is c_scaled = c^scalar mod n^2
   n_squared = public_key["n"] ** 2  # Compute n^2
   return pow(c, scalar, n_squared)  # Homomorphic scalar multiplication formula

if __name__ == "__main__":
    #for handling command line arguements
    if len(sys.argv) != 3:
        print("Usage: python homomorphic_scalar.py <file.enc> <scalar.txt>")
        sys.exit(1)
    # Loading of files at command line
    enc_file = sys.argv[1]  # Encrypted file
    scalar_file = sys.argv[2]  # Scalar file

    # Load the public key
    with open("public_key.json", "r") as pub_file:
        public_key = json.load(pub_file)

    # Load the ciphertext from the encrypted file
    with open(enc_file, "r") as infile:
        enc_data = json.load(infile)
        ciphertext = enc_data["ciphertext"]

    # Load the scalar value from the scalar file
    with open(scalar_file, "r") as scalarfile:
        scalar = int(scalarfile.read().strip())

    # Perform homomorphic scalar multiplication
    scaled_ciphertext = homomorphic_scalar(public_key, ciphertext, scalar)

    # Save the resulting ciphertext to a .enc file
    result_file = "Homomorphic_results/homomorphic_scalar_result.enc"
    with open(result_file, "w") as outfile:
        json.dump({"ciphertext": scaled_ciphertext}, outfile)

    print(f"Homomorphic scalar multiplication result saved to '{result_file}'.")
