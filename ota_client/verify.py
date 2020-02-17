#!/usr/bin/env python3

"""
    Verify the complete setup and compiled yaota8266.bin if exists
"""

import hashlib
import sys
from binascii import unhexlify
from pathlib import Path

from ota_client.gen_keys import RsaPrivKeyNotFoundError
from ota_client.rsa_sign import RsaSign

BASE_PATH = Path(__file__).parent.parent  # .../yaota8266/

YAOTA8266_FILENAME = 'yaota8266.bin'  # .../yaota8266/yaota8266.bin
CONFIG_FILENAME = 'config.h'  # .../yaota8266/config.h


def verify_setup(skip_bin=False):
    exit_code = 0

    try:
        rsa_sign = RsaSign()
    except RsaPrivKeyNotFoundError as err:
        print(f'ERROR: {err}')
        exit_code += 1
        rsa_sign = None

    # Check config.h

    config_path = Path(BASE_PATH, CONFIG_FILENAME)
    if not config_path.is_file():
        print(f'\n *** ERROR: {CONFIG_FILENAME} not found. Please create first!', file=sys.stderr)
        exit_code += 1
    else:
        print(f'{CONFIG_FILENAME} exists, ok.')
        # Check RSA modulus line in config.h
        if rsa_sign is not None:
            rsa_modulus_line = rsa_sign.get_config_define_line()
            with config_path.open('r') as f:
                if rsa_modulus_line not in f.read():
                    print(
                        '\n *** ERROR: "#define MODULUS" line in config.h seems to be wrong!',
                        file=sys.stderr)
                    rsa_sign.dump_modulus()
                    exit_code += 1
                else:
                    print(f'{CONFIG_FILENAME} check, ok.')

    if skip_bin:
        # Don't check existing yaota8266.bin
        sys.exit(exit_code)

    # Check yaota8266.bin

    yaota8266_bin_path = Path(BASE_PATH, YAOTA8266_FILENAME)
    if not yaota8266_bin_path.is_file():
        print(
            f'\n *** ERROR: {YAOTA8266_FILENAME} not found. Please compile first!',
            file=sys.stderr)
        exit_code += 1
    else:
        print(f'{YAOTA8266_FILENAME} exists, ok.')
        if rsa_sign is None:
            print(f'Can not check {YAOTA8266_FILENAME} because RSA keys not exists.')
        else:
            # Check if same RSA modulus line was used
            with yaota8266_bin_path.open('rb') as f:
                bin = f.read()

            bin_sha256 = hashlib.sha256(bin)
            print(f'{YAOTA8266_FILENAME} SHA256: {bin_sha256.hexdigest()}')

            modulus = rsa_sign.comps['modulus']
            modulus_bin = b''.join([unhexlify(value) for value in modulus[3:].split(':')])

            pos = bin.find(modulus_bin)
            if pos == -1:
                print(
                    f'\n *** ERROR: {YAOTA8266_FILENAME} seems to compiled with a other RSA priv.key!'
                    f' Please recompile.', file=sys.stderr)
                exit_code += 1
            else:
                print(f'RSA modulus found at {hex(pos)}')
                print(f'{YAOTA8266_FILENAME} was created with the current RSA priv.key, ok.')

    sys.exit(exit_code)
