import base64
import os
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import padding_pkcs7

input = b"YELLOW SUBMARINE"
input_padding = padding_pkcs7(input, 128)

print(input_padding)