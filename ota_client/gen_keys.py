#!/usr/bin/env python3
import shutil
import subprocess
import sys
from pathlib import Path

BITS = 512
EXPONENT = 3
RSA_PRIVATE_KEY = 'priv.key'
RSA_PUBLIC_KEY = 'pub.key'
OTA_CLIENT_PATH = Path(__file__).parent  # .../yaota8266/ota_client/
BASE_PATH = OTA_CLIENT_PATH.parent  # .../yaota8266/


class RsaPrivKeyNotFoundError(FileNotFoundError):
    """
    The RSA private key file 'priv.key' doesn't exists, yet.
    """
    pass


def get_rsa_priv_path(must_exists=False):
    rsa_priv_path = Path(OTA_CLIENT_PATH, RSA_PRIVATE_KEY)
    if must_exists and not rsa_priv_path.is_file():
        raise RsaPrivKeyNotFoundError(f'RSA key file not found here {rsa_priv_path}')
    return rsa_priv_path


def get_rsa_pub_path():
    return Path(OTA_CLIENT_PATH, RSA_PUBLIC_KEY)


def verbose_subprocess_call(*args):
    args = [str(arg) for arg in args]
    print(' '.join(args))
    subprocess.check_call(
        args,
        universal_newlines=True,
        cwd=str(OTA_CLIENT_PATH)  # store and use 'priv.key' in .../yaota8266/ota_client/
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


def update_config():
    config_h_path = Path(BASE_PATH, 'config.h')  # .../yaota8266/config.h
    if not config_h_path.is_file():
        config_h_example_path = Path(BASE_PATH, 'config.h.example')
        print(
            f'Generate {config_h_path.relative_to(BASE_PATH)}'
            f' from {config_h_example_path.relative_to(BASE_PATH)}'
        )
        shutil.copy(config_h_example_path, config_h_path)
    else:
        print(f'{config_h_path.relative_to(BASE_PATH)} exitst, ok.')

    from ota_client.rsa_sign import RsaSign
    rsa_sign = RsaSign()
    rsa_modulus_line = rsa_sign.get_config_define_line()

    with config_h_path.open('r') as f:
        content = f.read()

    if rsa_modulus_line in content:
        print(f'Current RSA modulus line found in {config_h_path.relative_to(BASE_PATH)}, ok.')
        return

    print(f'Update RSA modulus line in: {config_h_path.relative_to(BASE_PATH)}')
    new_lines = []
    for line in content.splitlines():
        if line.startswith('#define MODULUS'):
            line = rsa_modulus_line
        new_lines.append(line)
    new_content = '\n'.join(new_lines)

    if rsa_modulus_line not in new_content:
        print('ERROR: RSA modulus line not found!')
        sys.exit(1)

    with config_h_path.open('w') as f:
        f.write(new_content)

    print(f'{config_h_path.relative_to(BASE_PATH)} updates, ok.')
