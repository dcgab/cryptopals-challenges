from audioop import avg
import base64
import itertools
import math
import os
import sys
from typing import Dict, Tuple

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import find_key

input = bytes()
with open('./set1/challenge6_file.txt', 'r') as file:
    base64_input = ''
    for line in file:
        base64_input += line.rstrip('\r\n')
    input = base64.b64decode(base64_input)

MAX_KEY_SIZE = 40

all_keys = find_key(input, MAX_KEY_SIZE)

for key, score in all_keys.items():
    print(f"key: {key.decode('ascii')}\t\t\tscore: {score}")