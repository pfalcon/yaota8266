#!/usr/bin/env python3

import subprocess
from binascii import unhexlify
from pathlib import Path

RSA_PRIV_KEY = 'priv.key'

class RsaPrivKeyNotFoundError(FileNotFoundError):
    """
    The RSA private key file 'priv.key' doesn't exists, yet.
    """
    pass

class RsaSign:
    def __init__(self):
        self.comps = self.load_key()

    def load_key(self):
        cwd = Path(__file__).parent.resolve()
        if not Path(cwd, RSA_PRIV_KEY).is_file():
            raise RsaPrivKeyNotFoundError('RSA key file not found in %s' % cwd)

        output = subprocess.check_output(
            ['openssl', 'pkey', '-in', RSA_PRIV_KEY, '-text'],
            universal_newlines=True,
            cwd=str(cwd)  # load 'priv.key' in .../yaota8266/ota_client/
        )
        # print(output)

        comps = {}
        last_comp = None
        for line in output.splitlines():
            if line[0] != ' ' and line[-1] == ':':
                last_comp = line[:-1]
            elif line.startswith('    '):
                comps[last_comp] = comps.get(last_comp, "") + line.strip()

        # print(comps)

        assert 'modulus' in comps, f'modulus not found in: {comps!r}'
        assert 'privateExponent' in comps, f'privateExponent not found in: {comps!r}'

        return comps

    def get_config_define_line(self):
        return '#define MODULUS %s' % self.comps['modulus'][2:].replace(':', '\\x')

    def dump_modulus(self):
        print('Copy&paste this RSA modulus line into your config.h:')
        print('-' * 100)
        print(self.get_config_define_line())
        print('-' * 100)

    def dump_exponent(self):
        print('pe = %s' % self.comps['privateExponent'][2:].replace(':', '\\x'))

    def sign(self, to_sign):
        mod = self.comps['modulus']
        assert mod.startswith('00:')
        mod = mod[3:].replace(':', "")
        BITS = len(mod) // 2 * 8
    #    print('Key bits:', BITS)

        mod = int.from_bytes(unhexlify(mod), 'big')
        pe = int.from_bytes(unhexlify(self.comps['privateExponent'].replace(':', "")), 'big')

        pad_len = BITS // 8 - len(to_sign) - 3
    #    print('Pad length:', pad_len)
        assert pad_len >= 8

        buf = b'\0\x01' + (b'\xff' * pad_len) + b'\0' + to_sign
    #    print('Padded to-sign len:', len(buf))
        val = int.from_bytes(buf, 'big')
    #    print('Padded to-sign:', val, hex(val))

        sig = pow(val, pe, mod)
    #    print('Sig (int):', sig, hex(sig))
        sig_b = sig.to_bytes(BITS // 8, 'big')
    #    print(hexlify(sig_b))
        return sig_b


if __name__ == '__main__':
    rsa_sign = RsaSign()
    rsa_sign.dump_modulus()

    print('\nprivateExponent:')
    rsa_sign.dump_exponent()

    to_sign = b'foob\0'
    print(f'\nsigned {to_sign!r}:')
    print(rsa_sign.sign(to_sign))
