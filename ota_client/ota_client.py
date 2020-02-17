#!/usr/bin/env python3

import hashlib
import socket
import struct
import sys
import time
from pathlib import Path

# from Crypto.Cipher import AES
from ota_client.rsa_sign import RsaSign

# How many firmware data bytes are included in each packet.
# Set a conservative default. There were issues reported that
# UDP packet larger than 548 bytes don't get thru. Unfortunately,
# that means that even 512 payload bytes + headers don't fit.
BLK_SIZE = 256

AES_IV = b'\0' * 16
AES_KEY = b'\x01' * 16

SIGNED_FILE_EXTENSION = '.ota'

OTA_PORT = 8266
SOCKET_TIMEOUT = 0.3

# The first OTA package will be send this this broadcast address:
BROADCAST_ADDRESS = '255.255.255.255'


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
    def __init__(self, fname=None):
        self.fname = fname
        self.total_size = None
        self.rsa_sign = RsaSign()

        self.rsa_key = None
        self.last_aes_key = None
        self.last_seq = 0
        self.rexmit = 0

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(SOCKET_TIMEOUT)

        self.device_ip = BROADCAST_ADDRESS  # send first packet as broadcast
        self.next_update = 0
        self.start_time = 0

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

    def send_recv(self, offset, pkt, data_len):

        if self.last_seq == 1 and self.device_ip == BROADCAST_ADDRESS:
            print('wait for response...', end='')
        elif time.time() > self.next_update:
            duration = time.time() - self.start_time
            sended = offset + data_len
            throughput = sended / duration / 1024

            percent = 100 / self.total_size * sended

            print(f'{percent:.1f}% Sending #{self.last_seq} ({throughput:.1f} KBytes/s)')
            self.next_update = time.time() + 1

        while True:
            try:
                self.sock.sendto(pkt, (self.device_ip, OTA_PORT))
                try:
                    resp, server = self.sock.recvfrom(1024)
                except socket.timeout:
                    if self.last_seq == 1:
                        # no device has responded, yet
                        if time.time() > self.next_update:
                            print('.', end='', flush=True)
                            self.next_update = time.time() + 1
                        continue
                    else:
                        raise

                if self.start_time == 0:
                    self.start_time = time.time()

                # print('resp:', resp, len(resp))

                resp_seq = struct.unpack('<I', resp[:4])[0]
                if resp_seq != self.last_seq:
                    print('Unexpected seq no: %d (expected: %d)' % (resp_seq, self.last_seq))
                    continue

                resp = resp[4:]
                resp = self.decode_pkt(resp)
                # print('decoded resp:', resp)

                resp_op, resp_len, resp_off = struct.unpack('<HHI', resp[:8])
                # print('resp:', (resp_seq, resp_op, resp_len, resp_off))

                if resp_off != offset or resp_len != data_len:
                    print('Invalid resp')
                    continue

                if self.device_ip == BROADCAST_ADDRESS:
                    # set device IP address and send all next packages to this address
                    print('received from:', repr(server))
                    self.device_ip = server[0]

                break
            except socket.timeout:
                if time.time() > self.next_update:
                    print('t', end='', flush=True)
                    self.next_update = time.time() + 1

                # For such packets we don't expect reply
                if offset == 0 and data_len == 0:
                    break

                self.rexmit += 1

    def send_ota_end(self):
        # Repeat few times to minimize chance of being lost
        print('Send OTA end', end='', flush=True)
        for i in range(3):
            pkt = self.make_pkt(0, b'')
            self.sock.sendto(pkt, (self.device_ip, OTA_PORT))
            time.sleep(0.1)
            print('.', end='', flush=True)

    def live_ota(self):
        file_path = Path(self.fname)
        self.total_size = file_path.stat().st_size

        offset = 0
        with file_path.open('rb') as f:
            while True:
                chunk = f.read(BLK_SIZE)
                if not chunk:
                    break
                pkt = self.make_pkt(offset, chunk)
                self.send_recv(offset, pkt, len(chunk))
                offset += len(chunk)

        self.send_ota_end()
        print('Done, rexmits: %d' % self.rexmit)

        duration = time.time() - self.start_time
        throughput = self.total_size / duration / 1024

        print(f'Send {self.total_size} Bytes in {duration:.1f}sec ({throughput:.1f} KBytes/s)')

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

    def canned_ota(self):
        file_path = Path(self.fname)
        self.total_size = file_path.stat().st_size

        with file_path.open('rb') as f_in:
            # Skip signature
            f_in.read(10)
            while True:
                data = f_in.read(2)
                sz = struct.unpack('<H', data)[0]
                if not sz:
                    break
                data = f_in.read(sz)
                last_seq, op, data_len, offset = struct.unpack('<IHHI', data[:12])
                self.send_recv(offset, data, data_len)

        print('Done, rexmits: %d' % self.rexmit)

        duration = time.time() - self.start_time
        throughput = self.total_size / duration / 1024

        print(f'Send {self.total_size} Bytes in {duration:.1f}sec ({throughput:.1f} KBytes/s)')



