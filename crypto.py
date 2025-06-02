import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import os 
import sys 


secret_key = "G&<p/I+yJjDgiEY"
BLOCK_SIZE = 16
IV_BYTES_NEEDED = 12
TAG_SIZE_BYTES = BLOCK_SIZE


def get_decryptor(key, iv, tag):
    key = key.encode()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key)
    key = digest.finalize()
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor


def decrypt(text):
    encrypted_text = base64.b64decode(text)
    iv = encrypted_text[:IV_BYTES_NEEDED]
    tag = encrypted_text[IV_BYTES_NEEDED:IV_BYTES_NEEDED + TAG_SIZE_BYTES]
    encrypted_text = encrypted_text[IV_BYTES_NEEDED + TAG_SIZE_BYTES:]
    decryptor = get_decryptor(secret_key, iv, tag)
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    return decrypted_text.decode('utf-8')


def get_encryptor(key, iv):
    key = key.encode()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key)
    key = digest.finalize()
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor

def encrypt(text):
    iv = os.urandom(IV_BYTES_NEEDED)
    encryptor = get_encryptor(secret_key, iv)
    encrypted_text = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_text = iv + tag + encrypted_text
    return base64.b64encode(encrypted_text).decode('utf-8')


def decode_request_log():
    import pandas as pd
    import json
    import sys
    import ast
    
    count = 0
    df = pd.read_csv(sys.argv[1])
    for idx, row in df.iterrows():
        response = ast.literal_eval(decrypt(row["response"]))
        if response.get("data", {}).get("front", {}).get("fields", {}).get("id_number", "") == "079304034312":
            print(response)
        # if response["error"]["front"]["code"] != 0 or response["error"]["back"]["code"] != 0:
        #     print(response)
        #     print("----------")
        #     count += 1
        #     print(count)


if __name__ == "__main__":
    print(decrypt(sys.argv[1]))
