import base64
import os
import sys
import argparse
import pathlib
from typing import Tuple

from tabulate import tabulate

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import find_key, repeating_key_stream, xor_bytes

def parse_input() -> Tuple[str, bool]:
    """Parses CLI input

    Returns:
        Tuple[str, bool]: Encrypt input using XOR
    """

    args_dict = {
        'path': '',
        'input': '',
        'key': '',
        'invalid': False
    }

    parser = argparse.ArgumentParser(description='Encrypts data using repeating XOR key')
    parser.add_argument('--key', type=str, help='Key', default=40)
    parser.add_argument('filepath', nargs='?', default='')
    parser.add_argument('stdin', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    
    filepath = parser.parse_args().filepath
    
    if not sys.stdin.isatty():
        stdin = parser.parse_args().stdin.read().splitlines()
    else:
        stdin = []

    args_dict['key'] = parser.parse_args().key

    if len(filepath) > 0 and len(stdin) == 0 and len(args_dict['key']) > 0:
        args_dict['path'] = filepath
    elif len(filepath) == 0 and len(stdin) > 0 and len(args_dict['key']) > 0:
        args_dict['input'] = stdin[0]
    else:
        args_dict['invalid'] = True
    
    return args_dict

def read_file(filepath: str) -> str:
    output = ''
    with open(pathlib.Path(filepath), 'r') as file:
        output = file.read()
    return output

def main():
    data = bytes()
    options = parse_input()

    if options['invalid'] == True:
        print('Invalid input')
        return
    else:
        if options['path']:
            data = read_file(options['path']).encode('ascii')
        elif options['input']:
            data = options['input'].encode('ascii')

    encrypted = xor_bytes(repeating_key_stream(options['key'].encode('ascii'), len(data)), data)
    print(base64.b64encode(encrypted).decode('ascii'))


if __name__ == '__main__':
    main()