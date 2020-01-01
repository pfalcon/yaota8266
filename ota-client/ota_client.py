#!/usr/bin/env python3

import argparse
import asyncio
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

OTA_PORT = 8266
SOCKET_TIMEOUT = 10

DNS_SERVER = '8.8.8.8'  # Google DNS Server ot get own IP
ENCODING = 'utf-8'


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

    async def send_recv(self, reader, writer, offset, pkt, data_len):
        while True:
            try:
                print('Sending # %d' % self.last_seq)
                # print('send:', pkt)
                writer.write(pkt)
                await writer.drain()
                resp = await reader.read(1024)
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

    async def send_ota_end(self, writer):
        # Repeat few times to minimize chance of being lost
        for i in range(3):
            pkt = self.make_pkt(0, b'')
            writer.write(pkt)
            await writer.drain()
            time.sleep(0.1)

    async def live_ota(self, reader, writer):
        offset = 0
        with open(self.fname, 'rb') as f:
            while True:
                chunk = f.read(BLK_SIZE)
                if not chunk:
                    break
                pkt = self.make_pkt(offset, chunk)
                await self.send_recv(reader, writer, offset, pkt, len(chunk))
                offset += len(chunk)

        await self.send_ota_end(writer)
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

    async def canned_ota(self, reader, writer):
        with open(self.fname, 'rb') as f_in:
            # Skip signature
            f_in.read(10)
            while True:
                data = f_in.read(2)
                sz = struct.unpack('<H', data)[0]
                if not sz:
                    break
                data = f_in.read(sz)
                last_seq, op, data_len, offset = struct.unpack('<IHHI', data[:12])
                await self.send_recv(reader, writer, offset, data, data_len)

        print('Done, rexmits: %d' % self.rexmit)


def get_ip_address():
    """
    :return: IP address of the host running this script.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(SOCKET_TIMEOUT)
    s.connect((DNS_SERVER, 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


class CommunicationError(RuntimeError):
    pass


def ip_range_iterator(own_ip, exclude_own):
    ip_prefix, own_no = own_ip.rsplit('.', 1)
    print(f'Scan:.....: {ip_prefix}.X')

    own_no = int(own_no)

    for no in range(1, 255):
        if exclude_own and no == own_no:
            continue

        yield f'{ip_prefix}.{no}'


class OtaStreamWriter(asyncio.StreamWriter):
    encoding = 'utf-8'

    async def write_text_line(self, text):
        self.write(b'%s\n' % text.encode('utf-8'))
        await self.drain()

    async def sendall(self, data):
        self.write(data)
        await self.drain()


async def open_connection(host=None, port=None):
    """A wrapper for create_connection() returning a (reader, writer) pair.

    Similar as asyncio.open_connection() but we use own OtaStreamWriter()
    """
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(limit=2 ** 16, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport, _ = await loop.create_connection(lambda: protocol, host, port)
    writer = OtaStreamWriter(transport, protocol, reader, loop)
    return reader, writer


class AsyncConnector:
    """
    Scan the own IP range and start callback if receiver found.
    """
    def __init__(self, callback):
        self.callback = callback

    async def port_scan_and_serve(self, port):
        own_ip = get_ip_address()
        print(f'Own IP....: {own_ip}')
        ips = tuple(ip_range_iterator(own_ip, exclude_own=True))

        print(f'Wait for receivers on port: {port}', end=' ', flush=True)
        clients = []
        while True:
            connections = [
                asyncio.wait_for(open_connection(ip, port), timeout=0.5)
                for ip in ips
            ]
            results = await asyncio.gather(*connections, return_exceptions=True)
            for ip, result in zip(ips, results):
                if isinstance(result, asyncio.TimeoutError):
                    continue
                elif not isinstance(result, tuple):
                    continue

                reader, writer = result

                print('Connected to:', ip)
                peername = writer.get_extra_info('peername')
                print(f'Connect to {peername[0]}:{peername[1]}')
                try:
                    await self.callback(reader, writer)
                except ConnectionResetError as e:
                    print(e)
                    continue
                clients.append(ip)

            if clients:
                return clients

            print('.', end='', flush=True)
            time.sleep(2)

    def scan(self, port):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            self.port_scan_and_serve(port=port)
        )


def cli():
    cmd_parser = argparse.ArgumentParser(description='yaota8266 (yet another esp8266 OTA) client')
    cmd_parser.add_argument('command', help='ota/sign/live-ota')
    cmd_parser.add_argument('file', help='file to process')
    args = cmd_parser.parse_args()

    if args.command == 'sign':
        # Sign firmware file for OTA
        OtaClient().sign(args.file)
        validate_ota(signed_filename(args.file))

    elif args.command == 'live-ota':
        # Do the OTA update for a device
        validate_ota(args.file)

        AsyncConnector(
            callback=OtaClient(args.file).live_ota
        ).scan(port=OTA_PORT)

    elif args.command == 'ota':
        validate_ota(args.file)

        AsyncConnector(
            callback=OtaClient(args.file).canned_ota
        ).scan(port=OTA_PORT)

    else:
        cmd_parser.error('Unknown command')


if __name__ == '__main__':
    cli()
