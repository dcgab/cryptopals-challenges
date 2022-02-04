import base64
import os
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import decrypt_AES_ECB

input = bytes()
with open('./set1/challenge7_file.txt', 'r') as file:
    base64_input = ''
    for line in file:
        base64_input += line.rstrip('\r\n')
    input = base64.b64decode(base64_input)

KEY = b"YELLOW SUBMARINE"

print(decrypt_AES_ECB(input, KEY).decode('ascii'))