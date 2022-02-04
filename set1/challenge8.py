import base64
import os


with open('./set1/challenge8_file.txt', 'r') as file:
    for line in file:
        input = bytes.fromhex(line)
        block_input = []
        for i in range(0, len(input), 16):
            block_input.append(input[i : i + 16])

        if len(block_input) != len(set(block_input)):
            print(input.hex())