#!/usr/bin/env python3

import argparse
import hashlib
import socket
import struct
import sys
import time

# from Crypto.Cipher import AES
from rsa_sign import RsaSign

# How many firmware data bytes are included in each packet.
# Set a conservative default. There were issues reported that
# UDP packet larger than 548 bytes don't get thru. Unfortunately,
# that means that even 512 payload bytes + headers don't fit.
BLK_SIZE = 256

AES_IV = b'\0' * 16
AES_KEY = b'\x01' * 16

SIGNED_FILE_EXTENSION = '.ota'


def signed_filename(fname):
    return fname + SIGNED_FILE_EXTENSION


def validate_ota(fname):
    print(f'Validate {fname}')
    if not fname.endswith(SIGNED_FILE_EXTENSION):
        # Maybe this helps, if somebody adds the normal firmware file
        # and not the signed one ;)
        print(
            f'Warning: Wrong file extensions! (default is: {SIGNED_FILE_EXTENSION!r})',
            file=sys.stderr)

    with open(fname, 'rb') as f_in:
        hasher = hashlib.sha1()
        sig = f_in.read(10)
        if sig != b'yaota8266\x01':
            print('Invalid OTA file signature!', file=sys.stderr)
            sys.exit(1)
        hasher.update(sig)
        while True:
            data = f_in.read(2)
            sz = struct.unpack('<H', data)[0]
            if not sz:
                break
            hasher.update(data)
            data = f_in.read(sz)
            hasher.update(data)
        hash = f_in.read(20)
        if hash != hasher.digest():
            print('Invalid OTA file checksum, file corrupted', file=sys.stderr)
            sys.exit(2)

    print('File is valid, ok.')


class OtaClient:
    def __init__(self):
        self.rsa_sign = RsaSign()

        self.rsa_key = None
        self.last_aes_key = None
        self.last_seq = 0
        self.rexmit = 0

    def add_digest(self, pkt):
        aes_key = AES_KEY
        # last_aes_key = aes_key
        # aes = AES.new(aes_key, AES.MODE_CBC, AES_IV)
        pad_len = (16 - len(pkt) % 16) % 16
        pkt += b'\0' * pad_len
        # pkt = aes.encrypt(pkt)

        digest = hashlib.sha1(pkt).digest()
        sig = self.rsa_sign.sign(aes_key + digest)
        self.last_seq += 1
        return struct.pack('<I', self.last_seq) + pkt + sig

    def make_pkt(self, offset, data):
        pkt = struct.pack('<HHI', 0, len(data), offset) + data
        pkt = self.add_digest(pkt)
        return pkt

    def decode_pkt(self, pkt):
        # aes = AES.new(last_aes_key, AES.MODE_CBC, AES_IV)
        # return aes.decrypt(pkt)
        return pkt

    def send_recv(self, s, offset, pkt, data_len):
        while True:
            try:
                print('Sending # %d' % self.last_seq)
                # print('send:', pkt)
                s.send(pkt)
                resp = s.recv(1024)
                # print('resp:', resp, len(resp))
                resp_seq = struct.unpack('<I', resp[:4])[0]
                if resp_seq != self.last_seq:
                    print('Unexpected seq no: %d (expected: %d)' % (resp_seq, self.last_seq))
                    continue
                resp = resp[4:]
                resp = self.decode_pkt(resp)
                # print('decoded resp:', resp)
                resp_op, resp_len, resp_off = struct.unpack('<HHI', resp[:8])
                print('resp:', (resp_seq, resp_op, resp_len, resp_off))
                if resp_off != offset or resp_len != data_len:
                    print('Invalid resp')
                    continue
                break
            except socket.timeout:
                # For such packets we don't expect reply
                if offset == 0 and data_len == 0:
                    break
                print('timeout')
                self.rexmit += 1

    def send_ota_end(self, s):
        # Repeat few times to minimize chance of being lost
        for i in range(3):
            pkt = self.make_pkt(0, b'')
            s.send(pkt)
            time.sleep(0.1)

    def live_ota(self, address, fname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((address, 8266))
        s.settimeout(0.3)

        offset = 0
        with open(fname, 'rb') as f:
            while True:
                chunk = f.read(BLK_SIZE)
                if not chunk:
                    break
                pkt = self.make_pkt(offset, chunk)
                self.send_recv(s, offset, pkt, len(chunk))
                offset += len(chunk)

        self.send_ota_end(s)
        print('Done, rexmits: %d' % self.rexmit)

    def sign(self, fname):
        print(f'Sign firmware file {fname}...')

        def hash_write(data):
            hasher.update(data)
            f_out.write(data)

        out_filename = signed_filename(fname)

        offset = 0
        with open(fname, 'rb') as f_in, open(out_filename, 'wb') as f_out:
            hasher = hashlib.sha1()
            hash_write(b'yaota8266\x01')
            while True:
                chunk = f_in.read(BLK_SIZE)
                if not chunk:
                    break
                pkt = self.make_pkt(offset, chunk)
                hash_write(struct.pack('<H', len(pkt)))
                hash_write(pkt)
                offset += len(chunk)

            for i in range(3):
                pkt = self.make_pkt(0, b'')
                hash_write(struct.pack('<H', len(pkt)))
                hash_write(pkt)

            f_out.write(struct.pack('<H', 0))
            f_out.write(hasher.digest())

        print(f'Signed file created: {out_filename}')

    def canned_ota(self, address, fname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((address, 8266))
        s.settimeout(0.3)

        with open(fname, 'rb') as f_in:
            # Skip signature
            f_in.read(10)
            while True:
                data = f_in.read(2)
                sz = struct.unpack('<H', data)[0]
                if not sz:
                    break
                data = f_in.read(sz)
                last_seq, op, data_len, offset = struct.unpack('<IHHI', data[:12])
                self.send_recv(s, offset, data, data_len)

        print('Done, rexmits: %d' % self.rexmit)


def cli():
    cmd_parser = argparse.ArgumentParser(description='yaota8266 (yet another esp8266 OTA) client')
    cmd_parser.add_argument('command', help='ota/sign/live-ota')
    cmd_parser.add_argument('file', help='file to process')
    cmd_parser.add_argument('-a', '--address', help='IP address of device to upgrade')
    args = cmd_parser.parse_args()

    if args.command == 'sign':
        # Sign firmware file for OTA
        OtaClient().sign(args.file)
        validate_ota(signed_filename(args.file))

    elif args.command == 'live-ota':
        # Do the OTA update for a device
        validate_ota(args.file)
        OtaClient().live_ota(args.address, args.file)

    elif args.command == 'ota':
        validate_ota(args.file)
        OtaClient().canned_ota(args.address, args.file)
        
    else:
        cmd_parser.error('Unknown command')


if __name__ == '__main__':
    cli()
