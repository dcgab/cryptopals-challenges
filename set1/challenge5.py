import math
import os
import sys
from typing import Dict, Tuple

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import repeating_key_stream, xor_bytes

input = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal""".encode('ascii')

key = 'ICE'.encode('ascii')
keystream = repeating_key_stream(key, len(input))

print(xor_bytes(input, keystream).hex())