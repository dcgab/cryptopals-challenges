from email import utils
import os
from string import ascii_letters
import sys
from typing import Dict, Tuple

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import xor_bytes, english_score, find_single_byte_xor

highest_score: Tuple[str, float, bytes] = ('', 0.0, bytes())

with open('./set1/challenge4_file.txt', 'r') as file:
    for line in file:
        cipher = bytes.fromhex(line)
        if len(cipher) > 0:
            score = list(find_single_byte_xor(cipher).items())[-1:]
            if len(score) > 0:
                if score[0][1][0] > highest_score[1]:
                    highest_score = (score[0][0], score[0][1][0], cipher)
        
print(f"{highest_score[0]}\t\t{highest_score[1]}")
print(f"Encrypted string: {highest_score[2].hex()}")