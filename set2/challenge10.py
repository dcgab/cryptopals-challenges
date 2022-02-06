import base64
import os
import sys
import timeit

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import read_base64_file, read_file, decrypt_AES_CBC, encrypt_AES_CBC, padding_pkcs7, unpadding_pkcs7

input = read_base64_file('./set2/challenge10_file.txt')

KEY = b'YELLOW SUBMARINE'
IV = bytes([0 for _ in range(16)])

print(decrypt_AES_CBC(input, KEY, IV).decode('ascii'))

# encrypted = encrypt_AES_CBC(padding_pkcs7(input, 128), KEY, IV)
# print(unpadding_pkcs7(decrypt_AES_CBC(encrypted, KEY, IV), 128).decode('ascii'))