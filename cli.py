#!/usr/bin/env python3

"""
    Easy access the ota-client CLI, e.g.:

        .../yaota8266$ ./cli.py -h
        usage: cli.py [-h] {sign,ota...
"""

from ota_client.__main__ import cli

if __name__ == '__main__':
    cli()
