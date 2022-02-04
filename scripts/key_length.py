import base64
import os
import sys
import argparse
import pathlib
from typing import Tuple
from helper import find_key_lengths
from tabulate import tabulate

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import find_key_lengths

def parse_input() -> Tuple[str, bool]:
    """Parses CLI input

    Returns:
        Tuple[str, bool]: Returns path or base64 input. True if path, False if base64 
    """

    args_dict = {
        'path': '',
        'base64': '',
        'max': 0,
        'invalid': False
    }

    parser = argparse.ArgumentParser(description='Calculates the lenght of the repeating XOR key')
    parser.add_argument('--max', type=int, help='Max key length', default=40)
    parser.add_argument('filepath', nargs='?', default='')
    parser.add_argument('stdin', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    
    filepath = parser.parse_args().filepath
    
    if not sys.stdin.isatty():
        stdin = parser.parse_args().stdin.read().splitlines()
    else:
        stdin = []

    args_dict['max'] = parser.parse_args().max

    if len(filepath) > 0 and len(stdin) == 0:
        args_dict['path'] = filepath
    elif len(filepath) == 0 and len(stdin) > 0:
        args_dict['base64'] = stdin[0]
    else:
        args_dict['invalid'] = True
    
    return args_dict

def read_file(filepath: str) -> bytes:
    output = bytes()
    with open(pathlib.Path(filepath), 'r') as file:
        base64_input = ''
        for line in file:
            base64_input += line.rstrip('\r\n')
        output = base64.b64decode(base64_input)
    return output

def main():
    data = bytes()
    options = parse_input()

    if options['invalid'] == True:
        print('Invalid input')
    else:
        if options['path']:
            data = read_file(options['path'])
        elif options['base64']:
            data = base64.b64decode(options['base64'])
    print(tabulate(list(find_key_lengths(data, options['max']).items())[::-1], headers=["Keylength", "Score"]))

if __name__ == '__main__':
    main()