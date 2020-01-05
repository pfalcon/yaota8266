#!/usr/bin/env python3

"""
    usage e.g.:
        .../yaota8266$ ./cli.py -h
"""

import argparse

from ota_client import gen_keys
from ota_client.ota_client import OtaClient, signed_filename, validate_ota
from ota_client.rsa_sign import RsaSign
from ota_client.verify import verify_setup


def generate_rsa_keys(args):
    """Generate RSA keys in '.../yaota8266/ota_client/' if not already exists"""
    gen_keys.generate_rsa_keys()


def print_rsa_modulus(args):
    """Print the RSA modulus line for copy&paste into config.h"""
    rsa_sign = RsaSign()
    print()
    rsa_sign.dump_modulus()
    print()


def sign(args):
    """Sign firmware file for OTA"""
    OtaClient().sign(args.file)
    validate_ota(signed_filename(args.file))


def ota(args):
    """Do the OTA update for a device"""
    validate_ota(args.file)
    OtaClient(args.file).live_ota()


def canned_ota(args):
    """Do the 'canned' OTA update for a device"""
    validate_ota(args.file)
    OtaClient(args.file).canned_ota()


def verify(args):
    """Check RSA key, config.h and compiled 'yaota8266.bin'"""
    verify_setup(skip_bin=args.skip_bin)


def cli():
    parser = argparse.ArgumentParser(description='yaota8266 (yet another esp8266 OTA) client')

    subparsers = parser.add_subparsers(title='subcommands')

    ##############################################################################################
    # generate_rsa_keys

    parser_generate_rsa_keys = subparsers.add_parser(
        'generate_rsa_keys', help=generate_rsa_keys.__doc__
    )
    parser_generate_rsa_keys.set_defaults(func=generate_rsa_keys)

    ##############################################################################################
    # print_rsa_modulus

    parser_print_rsa_modulus = subparsers.add_parser(
        'print_rsa_modulus', help=print_rsa_modulus.__doc__
    )
    parser_print_rsa_modulus.set_defaults(func=print_rsa_modulus)

    ##############################################################################################
    # sign

    parser_sign = subparsers.add_parser(
        'sign', help=sign.__doc__
    )
    parser_sign.add_argument('file', help='file to process')
    parser_sign.set_defaults(func=sign)

    ##############################################################################################
    # ota

    parser_ota = subparsers.add_parser(
        'ota', help=ota.__doc__
    )
    parser_ota.add_argument('file', help='file to process')
    parser_ota.set_defaults(func=ota)

    ##############################################################################################
    # canned_ota

    parser_canned_ota = subparsers.add_parser(
        'canned_ota', help=canned_ota.__doc__
    )
    parser_canned_ota.add_argument('file', help='file to process')
    parser_canned_ota.set_defaults(func=canned_ota)

    ##############################################################################################
    # verify

    parser_verify = subparsers.add_parser(
        'verify', help=verify.__doc__
    )
    parser_verify.add_argument(
        '--skip_bin',
        action='store_true',
        help='skip existing yaota8266.bin check')
    parser_verify.set_defaults(func=verify)

    ##############################################################################################

    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.error('Unknown command')

    args.func(args)


if __name__ == '__main__':
    cli()
