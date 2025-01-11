
#For this code, I took reference from https://www.youtube.com/watch?v=Yerhc9B2zjQ and https://github.com/mikeivanov/paillier/blob/master/paillier/paillier.py and then modified accordingly

import json
import sys

# Homomorphic addition
#  Performs homomorphic addition of two ciphertexts using the Paillier cryptosystem.
def homomorphic_add(public_key, c1, c2):
    # formula is c_sum = (c1 * c2) mod n^2
    n_squared = public_key["n"] ** 2
    return (c1 * c2) % n_squared

if __name__ == "__main__":
    #For Command Line handling
    if len(sys.argv) != 3:
        print("Usage: python homomorphic_addition.py <file1.enc> <file2.enc>")
        sys.exit(1)

 # Input encrypted files provided via command-line
    file1 = sys.argv[1]
    file2 = sys.argv[2]

    # Load the public key
    with open("public_key.json", "r") as pub_file:
        public_key = json.load(pub_file)

    # Load the ciphertexts from the encrypted files
    with open(file1, "r") as f1, open(file2, "r") as f2:
        enc_data1 = json.load(f1)
        enc_data2 = json.load(f2)
 # Read the JSON-encoded ciphertexts from the files
    ciphertext1 = enc_data1["ciphertext"]
    ciphertext2 = enc_data2["ciphertext"]

    # Perform homomorphic addition
    sum_ciphertext = homomorphic_add(public_key, ciphertext1, ciphertext2)

    # Save the result to a enc file
    result_file = "Homomorphic_results/homomorphic_addition_result.enc"
    with open(result_file, "w") as outfile:
        json.dump({"ciphertext": sum_ciphertext}, outfile)

    print(f"Homomorphic addition result saved to '{result_file}'.")
