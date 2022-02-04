from asyncore import read
import base64
import os
import random
import urllib.parse
import sys
from typing import Any, Callable, Dict, List

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

def decode_profile(profile_encoded: str):
    decoded = dict(urllib.parse.parse_qsl(profile_encoded))
    return {
        'email': decoded['email'],
        'uid': int(decoded['uid']),
        'role': decoded['role']
    }

def encode_profile(email: str, uid: int, role: str):
    return urllib.parse.urlencode({
        'email': email,
        'uid': uid,
        'role': role
    })

def profile_for(email: str):
    return encode_profile(email, 10, 'user')

decoded = decode_profile(profile_for('foo@bar.com'))
print(decoded)
encoded = encode_profile(decoded['email'], decoded['uid'], decoded['role'])
print(encoded)

# Attacker can check for ECB and block size
# Attacker must prefix until the end of output is at the end of the block
#   -> Can be checked when encrypted block stops changing
# Attacker can recover the rest to learn about the plaintext after input
#   -> Using ECB plaintext attack
# Attacker can delete everything after email or role field by deleting the next block if this resides in a seperate block
#   -> email=looong@adres.com|&uid=10&role=user
#   -> email=looong@adres.com&uid=10&role=|user
# How do we get a block containing "admin"?
#   -> email=looong@adres.com|admin[padding]|&uid=10&role=user
# Then paste the block including padding after the cut-off role
#   -> email=looong@adres.com&uid=10&role=|admin[padding]