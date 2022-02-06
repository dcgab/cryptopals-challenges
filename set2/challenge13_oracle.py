import os
import urllib.parse
import sys
import re
from typing import Any, Callable, Dict, List, Union

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(script_dir))

from helper import  decrypt_AES_ECB, gen_key, encrypt_AES_ECB, padding_pkcs7, unpadding_pkcs7

secret_key: bytes = None

def encode_profile(profile: Dict[str, Any]) -> str:
    return urllib.parse.urlencode({
        'email': profile['email'],
        'uid': profile['uid'],
        'role': profile['role']
    })

def decode_profile(profile_encoded: str) -> Dict[str, Any]:
    decoded = dict(urllib.parse.parse_qsl(profile_encoded))
    return {
        'email': decoded['email'],
        'uid': int(decoded['uid']),
        'role': decoded['role']
    }

def gen_profile_for(email: str) -> Dict[str, Any]:
    if re.fullmatch(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email) or True:
        return {
            'email': email,
            'uid': 10,
            'role': 'user'
        }
    else:
        raise ValueError('Error: invalid email')

def encrypt_profile(profile: Dict[str, Any]) -> bytes:
    global secret_key
    if secret_key is None:
        secret_key = gen_key(128)

    encoded_profile = encode_profile(profile)
    return encrypt_AES_ECB(padding_pkcs7(encoded_profile.encode('ascii'), 128), secret_key)

def decrypt_profile(encrypted_profile: bytes) -> bytes:
    global secret_key
    if secret_key is None:
        secret_key = gen_key(128)

    encoded_profile = unpadding_pkcs7(decrypt_AES_ECB(encrypted_profile, secret_key), 128).decode('ascii')
    print(encoded_profile)
    return decode_profile(encoded_profile)

def profile_for(email: str) -> bytes:
    profile = gen_profile_for(email)
    return encrypt_profile(profile)