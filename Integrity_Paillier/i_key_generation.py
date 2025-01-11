# Reference: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

from cryptography.hazmat.primitives.asymmetric import rsa  # For RSA key generation
from cryptography.hazmat.primitives import serialization  # For serializing RSA keys

import libnum  # Library for modular arithmetic
from sympy import randprime, gcd # Used for prime number generation and GCD calculation
import json # For saving keys to JSON files

# Function to compute the least common multiple (already explained)
def lcm(a, b):
    return int(a * b // gcd(a, b))

# Function to compute L(x) in Paillier decryption (already explained)
def L(x, n):
    return (x - 1) // n

# Paillier Key Generation (already explained)
def generate_paillier_keys(bits=1024):
    lower_bound = 2**(bits // 2 - 1)
    upper_bound = 2**(bits // 2) - 1

    p = randprime(lower_bound, upper_bound)
    q = randprime(lower_bound, upper_bound)
    while p == q or gcd(p * q, (p - 1) * (q - 1)) != 1:
        q = randprime(lower_bound, upper_bound)

    n = int(p * q)
    lambda_n = lcm(p - 1, q - 1)
    g = n + 1
    n_squared = n * n
    g_lambda = pow(int(g), int(lambda_n), int(n_squared))
    Lg = L(g_lambda, n)
    mu = libnum.invmod(Lg, n)

    return {"n": n, "g": g}, {"lambda": lambda_n, "mu": mu}

# RSA Key Generation for Digital Signatures
def generate_rsa_keys():
    # Commonly used public exponent and key size in bits
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Extract the public key from the private key
    public_key = private_key.public_key()

    # Serialize private key to pem formatt
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, #PEM Formatt
        format=serialization.PrivateFormat.TraditionalOpenSSL, #open ssl formatt
        encryption_algorithm=serialization.NoEncryption() # no encryption
    )

     # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, #PEM Formatt
        format=serialization.PublicFormat.SubjectPublicKeyInfo # Public Key Formatt
    )

    return private_key_pem, public_key_pem

if __name__ == "__main__":
    # Generate Paillier keys
    paillier_public_key, paillier_private_key = generate_paillier_keys(bits=1024)

    # Save Paillier keys to JSON
    # Referecne: https://www.geeksforgeeks.org/reading-and-writing-json-to-a-file-in-python/
    with open("public_key_Paillier.json", "w") as pub_file:
        json.dump(paillier_public_key, pub_file)
    with open("private_key_Paillier.json", "w") as priv_file:
        json.dump(paillier_private_key, priv_file)

    # Generate RSA keys for digital signatures
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    # Save RSA keys to files in pem formatt
    with open("rsa_private_key.pem", "wb") as priv_file:
        priv_file.write(rsa_private_key)
    with open("rsa_public_key.pem", "wb") as pub_file:
        pub_file.write(rsa_public_key)

    print("Keys generated and saved.")
