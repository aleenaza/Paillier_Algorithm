
# I took reference for key generation from https://asecuritysite.com/encryption/pal_ex and modified it accordingly.
    

import libnum  # Library for modular arithmetic
from sympy import randprime, gcd # Used for prime number generation and GCD calculation
import json # For saving keys to JSON files

# Function to compute the least common multiple
def lcm(a, b):
    return int(a * b // gcd(a, b))

# Function to compute L(x) in Paillier decryption
def L(x, n):
    return (x - 1) // n

# Keys Generation
def generate_keys(bits=1024): #Bit size of the keys. Recommended values are 512, 1024, or higher.

 # Generate two large primes, p and q
    lower_bound = 2**(bits // 2 - 1) 
    upper_bound = 2**(bits // 2) - 1

    p = randprime(lower_bound, upper_bound)  # SymPy function for random prime generation
    q = randprime(lower_bound, upper_bound)

    # Ensure p and q are distinct and satisfy GCD conditions
    while p == q or gcd(p * q, (p - 1) * (q - 1)) != 1:
        q = randprime(lower_bound, upper_bound)


    # Compute n = p * q and lambda_n = lcm(p - 1, q - 1)
    n = int(p * q)
    lambda_n = lcm(p - 1, q - 1)


     # Set g = n + 1 (common choice in Paillier)
    g = n + 1
    g = n + 1
     # Compute n^2 (used in encryption and decryption)
    n_squared = n * n
     # Compute mu, the modular inverse of L(g^lambda mod n^2)
    g_lambda = pow(int(g), int(lambda_n), int(n_squared))  #g^lambda mod n^2
    Lg = L(g_lambda, n)
    mu = libnum.invmod(Lg, n)

    return {"n": n, "g": g}, {"lambda": lambda_n, "mu": mu}

if __name__ == "__main__":
    public_key, private_key = generate_keys(bits=1024)

    # Save the keys to JSON files
    #took reference from the moodle file "File Encryption Demo.pdf" and https://www.geeksforgeeks.org/reading-and-writing-json-to-a-file-in-python/

    with open("public_key.json", "w") as pub_file:
        json.dump(public_key, pub_file)
    with open("private_key.json", "w") as priv_file:
        json.dump(private_key, priv_file)

    print("Keys are created and saved to 'public_key.json' and 'private_key.json'.")
