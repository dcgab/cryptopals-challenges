import base64
import itertools
import math
from multiprocessing.sharedctypes import Value
import os
from pydoc import plain
import random
from string import ascii_letters
from typing import Callable, Dict, List, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms

def read_base64_file(path: str) -> bytes:
    input = bytes()
    with open(path, 'r') as file:
        base64_input = ''
        for line in file:
            base64_input += line.rstrip('\r\n')
        input = base64.b64decode(base64_input)
    return input

def read_file(path: str) -> bytes:
    input = ''
    with open(path, 'r') as file:
        for line in file:
            input += line
    return input.encode('ascii')

def xor_bytes(bytesA: bytes, bytesB: bytes) -> bytes:
    return bytes(byteA ^ byteB for (byteA, byteB) in zip(bytesA, bytesB))

def english_score(string: str, byte_length: int) -> float:
    score: float = 0.0
    freq_table = {' ': 0.1900, 'e': 0.1202, 't': 0.0910, 'a': 0.0812, 'o': 0.0768, 'i': 0.0731, 'n': 0.0695,
                    's': 0.0628, 'r': 0.0602, 'h': 0.0592, 'd': 0.0432, 'l': 0.0398, 'u': 0.0288,
                    'c': 0.0271, 'm': 0.0261, 'f': 0.0230, 'y': 0.0211, 'w': 0.0209, 'g': 0.0203,
                    'p': 0.0182, 'b': 0.0149, 'v': 0.0111, 'k': 0.0069, 'x': 0.0017, 'q': 0.0011,
                    'j': 0.0010, 'z': 0.0007}
    for char in string:
        if char in ascii_letters or char == ' ':
            score += freq_table.get(char.lower())
    score /= byte_length
    
    return score

def find_single_byte_xor(input: bytes) -> Dict[str, Tuple[float, int]]:
    outputs: Dict[str, Tuple[float, int]] = {}

    for key in range(0, 0x80):
        keystream = bytes([key] * len(input))
        
        try:
            decrypted = xor_bytes(input, keystream).decode('ascii')
        except UnicodeDecodeError:
            continue

        # illegal_char = False
        # for decrypted_char in decrypted:
        #     if ord(decrypted_char) < 0x20 or ord(decrypted_char) > 0x7E:
        #         illegal_char = True

        outputs[decrypted] = (english_score(decrypted, len(decrypted)), key)

    return {k: v for k, v in sorted(outputs.items(), key=lambda item: item[1][0])}

def repeating_key_stream(key: bytes, length: int) -> bytes:
    return (key*math.ceil(length / len(key)))[:length]

def hamming_distance(inputA: bytes, inputB: bytes):
    distance = 0
    difference = xor_bytes(inputA, inputB)
    for diff_byte in difference:
        for i in range(0, 8):
            distance += (diff_byte >> i) & 1

    return distance

def find_key_lengths(input: bytes, max_key_length: int) -> Dict[int, float]:
    keylength_score: Dict[int, float] = {}
    # Try key length of length 2 to max key length
    for key_length in range(2, max_key_length+1):
        test_values = []
        # Get four blocks to test
        for i in range(0, 4):
            test_values.append(input[key_length * i : key_length * (i + 1)])

        # Create pair of every combination of key lengths and calculate their average hamming distances
        avg_distance = sum([hamming_distance(test_block_1, test_block_2) / (key_length*8) for test_block_1, test_block_2 in list(itertools.combinations(test_values, 2))]) / 6
        keylength_score[key_length] = avg_distance

    # Return dictionary sorted by the hamming distance
    return {k: v for k, v in sorted(keylength_score.items(), key=lambda item: item[1])}

def find_key(input:bytes, max_key_size: int) -> Dict[bytes, float]:
    likely_keys: List[List[bytearray]] = []
    for key_length, _ in list(find_key_lengths(input, max_key_size).items())[0:5]:

        # Transpose some blocks so that each n'th block contains all n'th characters
        n_blocks = len(input) // key_length
        blocks = [bytearray(n_blocks) for _ in range(key_length)]
        # Get the blocks to test
        for i in range(0, n_blocks):
            block = input[key_length * i : key_length * (i + 1)]
            for j in range(0, key_length):
                blocks[j][i] = block[j]

        # Find the key using a single byte xor using English histogram
        # decrypted_blocks = [bytearray(key_length) for _ in range(n_blocks)]
        used_keys: List[bytearray] = [bytearray(key_length) for _ in range(5)]

        # Find key for top 5 best results
        for i in range(5):
            used_key = bytearray(key_length)
            for j in range(key_length):
                result = list(find_single_byte_xor(blocks[j]).items())[-i - 1]
                used_key[j] = result[1][1]
            used_keys[i] = used_key
        
        likely_keys.append(used_keys)


    # Test each key to see if it outputs English text using
    flattened = [bytes(key) for key_list in likely_keys for key in key_list]
    score_dict: Dict[bytes, float] = {}
    for key in flattened:
        keystream = repeating_key_stream(key, len(key))
        output = xor_bytes(keystream, input)
        score_dict[key] = english_score(str(output), len(output))

    return {k: v for k, v in sorted(score_dict.items(), key=lambda item: item[1])}

def encrypt_AES_ECB(input: bytes, key: bytes):
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return (encryptor.update(input) + encryptor.finalize())

def decrypt_AES_ECB(input: bytes, key: bytes):
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return (decryptor.update(input) + decryptor.finalize())

# async def _decrypt_AES_ECB_async(input: bytes, key: bytes):
#     decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
#     return (decryptor.update(input) + decryptor.finalize())

# async def _decrypt_AES_ECB_parallel(input: bytes, key: bytes):
#     input_blocks: List[bytes] = []
#     for i in range(0, len(input), 16):
#         input_blocks.append(input[i:i+16])

#     return await asyncio.gather(*[_decrypt_AES_ECB_async(input_blocks[i], key) for i in range(len(input_blocks))])

# def decrypt_AES_ECB_parallel(input: bytes, key: bytes):
#     return b''.join(asyncio.run(_decrypt_AES_ECB_parallel(input, key)))

def encrypt_AES_CBC(input: bytes, key: bytes, iv: bytes) -> bytes:
    output = bytearray()
    prev_block_output = iv

    for i in range(0, len(input), 16):
        plaintext = input[i:i+16]
        block_input = xor_bytes(plaintext, prev_block_output)
        prev_block_output = encrypt_AES_ECB(block_input, key)
        output.extend(prev_block_output)

    return output

def decrypt_AES_CBC(input: bytes, key: bytes, iv: bytes) -> bytes:
    
    decrypted_ecb = decrypt_AES_ECB(input, key)
    xor_data = iv + input[0:-16]

    return xor_bytes(decrypted_ecb, xor_data)

def padding_pkcs7(input: bytes, block_size: int) -> bytes:
    block_size //= 8
    output = bytearray(input)

    n_padding = block_size - (len(input) % block_size)
    if n_padding == 0:
        n_padding = block_size

    output.extend([n_padding]*n_padding)

    return bytes(output)

def unpadding_pkcs7(input: bytes, block_size: int) -> bytes:
    block_size //= 8
    n_padding = list(input)[-1]
    return input[0:-n_padding]

def gen_key(length: int) -> bytes:
    """Generates a random string of bytes for a key

    Args:
        length (int): Key length in bits

    Raises:
        ValueError: Length must be a multiple of 8

    Returns:
        bytes: Key
    """
    if length % 8 != 0:
        raise ValueError('Length must be a multiple of 8')
    return os.urandom(length // 8)

def find_block_size(function: Callable[[bytes], bytes]):
    output_len = len(function(b'A'))
    counter = 2
    while True:
        new_len = len(function(b'A'*counter))
        if new_len > output_len:
            return (new_len - output_len) * 8
        counter += 1

def uses_ecb(function: Callable[[bytes], bytes], block_size: int) -> bool:
    input = function(b'A'*(block_size*10))
    block_input: List[str] = []
    for i in range(0, len(input), 16):
        block_input.append(input[i : i + 16].hex())

    return len(block_input) != len(set(block_input))

def find_ecb_attack_offset(oracle: Callable[[bytes], bytes]) -> Tuple[int, int]:
    block_size_bytes = find_block_size(oracle) // 8
    for i in range(0, block_size_bytes):
        # Start with input with length of the block size * 2 and add bytes until two blocks are identical
        # The added bytes is the offset and the block offset is the block we are comparing - 1
        input = (b'B'*i) + (b'A'*(block_size_bytes*2))
        output = oracle(input)

        prev_block: bytes = b''
        for j in range(0, len(output), block_size_bytes):
            curr_block = output[j : j + block_size_bytes]
            if (prev_block == curr_block) and (prev_block not in oracle(b'')):
                return i, (j // block_size_bytes) - 1
            prev_block = curr_block

def recover_ECB_prepend_plaintext(oracle: Callable[[bytes], bytes]) -> bytes:
    input_offset, block_offset = find_ecb_attack_offset(oracle)

    block_size = find_block_size(oracle)
    is_ecb = uses_ecb(oracle, block_size)
    recovered_plaintext: bytearray = bytearray()
    lookup: Dict[bytes, int] = {}
    block_size_bytes = block_size // 8
    prefix_offset = b'B'*input_offset
    prefix_init =  b'A'*block_size_bytes

    for _ in range(len(oracle(b''))):
        # Calculate in which block to recover the byte 
        lookup_block = (len(recovered_plaintext) // block_size_bytes) + block_offset
        # Calculate the length of the prefix
        prefix_length = (15 - len(recovered_plaintext)) % block_size_bytes

        prefix = prefix_offset + prefix_init[0:prefix_length]

        # Create a lookup table for all possible bytes
        for i in range(0x80):
            # prefix + recovered_plaintext is always a multiple of the block size - 1
            input_block = prefix + recovered_plaintext + bytes([i])
            # get the encrypted block in which we apply our brute-force byte
            encrypted_block = oracle(input_block)[lookup_block * block_size_bytes : (lookup_block + 1) * block_size_bytes]
            # print(input_block.hex(), oracle(input_block).hex())
            # Save this block together with the plaintext byte
            lookup[encrypted_block] = i

        # Retrieve the plaintext byte using the lookup table
        recovered_byte = lookup.get(oracle(prefix)[lookup_block * block_size_bytes : (lookup_block + 1) * block_size_bytes])
        # Stop when no bytes are found
        if recovered_byte is None:
            break

        recovered_plaintext.append(recovered_byte)
        lookup.clear()
        
    return bytes(recovered_plaintext)

def format_blocks(input: bytes, blocksize: int):
    blocksize_bytes = blocksize // 8
    sep = '---'
    block_list = [input[i * blocksize_bytes : (i+1) * blocksize_bytes].hex() for i in range(0, len(input), blocksize_bytes)]
    print(block_list)
    return sep.join(block_list)
