from email import utils
import os
from string import ascii_letters
import sys
from typing import Dict

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import xor_bytes, english_score, find_single_byte_xor

input = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

outputs = find_single_byte_xor(input)

for (decrypted, score) in outputs.items():
    print("{0}\t\t\t{1}".format(decrypted, score[0]))