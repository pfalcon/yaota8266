"""
    Just print the RSA modulus line
"""

from rsa_sign import RsaSign

if __name__ == '__main__':
    rsa_sign = RsaSign()
    print()
    rsa_sign.dump_modulus()
    print()
