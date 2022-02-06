import base64
from itertools import groupby
import os
import random
import urllib.parse
import sys
import re
from typing import Any, Callable, Dict, List, Tuple, Union

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import  decrypt_AES_ECB, find_ecb_attack_offset, gen_key, encrypt_AES_ECB, padding_pkcs7, unpadding_pkcs7, uses_ecb, find_block_size, format_blocks
from challenge13_oracle import profile_for, decrypt_profile

token = profile_for('foo@bar.com')

def oracle(input: bytes) -> bytes:
    return profile_for('a@a.nl' + input.decode('ascii'))

        

block_size = find_block_size(oracle)
block_size_bytes = find_block_size(oracle) // 8

print("Block size: {0}".format(block_size))
print("Uses ECB: {0}".format(uses_ecb(oracle, block_size)))

offset_nr, block_nr = find_ecb_attack_offset(oracle)

print("Offset: {0}".format(offset_nr))
print("Block: {0}".format(block_nr))

role = b'user'
offset_string = (b'A'*(offset_nr))
admin_string = offset_string + padding_pkcs7(role, block_size)
admin_encrypted = oracle(admin_string)[block_nr * block_size_bytes : (block_nr + 1) * block_size_bytes]

print(f"Offset encrypted:\t{format_blocks(oracle(offset_string), 128)}\n")
print(f"Admin encrypted:\t{oracle(admin_string).hex()}")

completing_amount = None
for i in range(15):
    encrypted_len = len(oracle(b'A'*i))
    added_len = len(oracle(b'A'*(i+1)))
    if encrypted_len != added_len:
        completing_amount = i+1

role_cutoff = oracle(b'A' * (completing_amount + len(role)))[0:-block_size_bytes]
token_admin = role_cutoff + admin_encrypted

print(decrypt_profile(admin_encrypted))

# recovered_plaintext = recover_ECB_prepend_plaintext(oracle)

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