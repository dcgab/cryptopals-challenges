from asyncore import read
import os
import random
import sys
from typing import List

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import read_file, encrypt_AES_CBC, encrypt_AES_ECB, padding_pkcs7, gen_key, is_ecb

def encryption_oracle(input: bytes):
    key = gen_key(128)
    input_modified = os.urandom(random.randrange(5, 11)) + input + os.urandom(random.randrange(5, 11))
    output = bytes()
    if os.urandom(1)[0] & 1:
        # Use ECB
        output = encrypt_AES_ECB(padding_pkcs7(input_modified, 128), key)
    else:
        # Use CBC
        iv = gen_key(128)
        output = encrypt_AES_CBC(padding_pkcs7(input, 128), key, iv)

    return output

for i in range(20):
    encrypted = encryption_oracle(b'a'*160)
    print(is_ecb(encrypted))

