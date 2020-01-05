#!/usr/bin/env python3

"""
    Easy access the ota-client CLI, e.g.:

        .../yaota8266$ ./cli.py -h
        usage: cli.py [-h] {sign,ota,canned_ota} ...

        yaota8266 (yet another esp8266 OTA) client

        optional arguments:
          -h, --help            show this help message and exit

        subcommands:
          {sign,ota,canned_ota}
            sign                Sign firmware file for OTA
            ota                 Do the OTA update for a device
            canned_ota          Do the "canned" OTA update for a device
"""

from ota_client.__main__ import cli

if __name__ == '__main__':
    cli()
