#!/usr/bin/env python3

import subprocess
from pathlib import Path

BITS = 512
EXPONENT = 3
RSA_PRIVATE_KEY = 'priv.key'
RSA_PUBLIC_KEY = 'pub.key'
BASE_PATH = Path(__file__).parent


def get_rsa_priv_path():
    return Path(BASE_PATH, RSA_PRIVATE_KEY)


def get_rsa_pub_path():
    return Path(BASE_PATH, RSA_PUBLIC_KEY)


def verbose_subprocess_call(*args):
    print(' '.join(args))
    subprocess.check_call(
        args,
        universal_newlines=True,
        cwd=str(BASE_PATH)  # store and use 'priv.key' in .../yaota8266/ota_client/
    )


def generate_rsa_keys():
    rsa_priv_path = get_rsa_priv_path()
    if rsa_priv_path.is_file():
        print(f'\nKeys already created, here: {rsa_priv_path}, ok.\n')
        return

    verbose_subprocess_call('openssl', 'genrsa', '-out', RSA_PRIVATE_KEY, f'-{EXPONENT}', BITS)
    verbose_subprocess_call(
        'openssl', 'rsa', '-in', RSA_PRIVATE_KEY,
        '-pubout', '-out', RSA_PUBLIC_KEY
    )
    verbose_subprocess_call('openssl', 'pkey', '-in', RSA_PRIVATE_KEY, '-text')
