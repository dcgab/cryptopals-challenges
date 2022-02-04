from asyncore import read
import base64
import os
import random
import sys
from typing import Callable, Dict, List

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import  gen_key, encrypt_AES_ECB, padding_pkcs7, unpadding_pkcs7, uses_ecb, find_block_size, recover_ECB_prepend_plaintext

secret_key: bytes = None

def encryption_oracle(input: bytes):
    global secret_key
    if secret_key is None:
        secret_key = gen_key(128)

    input_modified = input + base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK')
    return encrypt_AES_ECB(padding_pkcs7(input_modified, 128), secret_key)

# encrypted = encryption_oracle(b'Hello there')
block_size = find_block_size(encryption_oracle)
print(f"Block size: {block_size}")
print(f"Is ECB: {uses_ecb(encryption_oracle, block_size)}")

recovered_plaintext = recover_ECB_prepend_plaintext(encryption_oracle)
print(unpadding_pkcs7(recovered_plaintext, 128))