#!/usr/bin/env python3
import sys
import struct
import socket
import time
import hashlib
import argparse

from Crypto.Cipher import AES
import rsa_sign


BLK_SIZE = 1024

AES_IV = b"\0" * 16
AES_KEY = b"\x01" * 16

rsa_key = None
last_aes_key = None
last_seq = 0


def add_digest(pkt):
    global last_aes_key, last_seq
    aes_key = AES_KEY
    last_aes_key = aes_key
    aes = AES.new(aes_key, AES.MODE_CBC, AES_IV)
    pad_len = (16 - len(pkt) % 16) % 16
    pkt += b"\0" * pad_len
    pkt = aes.encrypt(pkt)

    digest = hashlib.sha1(pkt).digest()
    sig = rsa_sign.sign(rsa_key, aes_key + digest)
    last_seq += 1
    return struct.pack("<I", last_seq) + pkt + sig


def decode_pkt(pkt):
    global last_aes_key
    aes = AES.new(last_aes_key, AES.MODE_CBC, AES_IV)
    return aes.decrypt(pkt)


def live_ota():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((args.address, 8266))
    s.settimeout(0.3)

    offset = 0
    with open(args.file, "rb") as f:
        rexmit = 0
        while True:
            chunk = f.read(BLK_SIZE)
            if not chunk:
                break
            pkt = struct.pack("<HHI", 0, len(chunk), offset) + chunk
            pkt = add_digest(pkt)
    #        print("pkt:", pkt)
            while 1:
                try:
                    print("Sending #%d" % last_seq)
                    s.send(pkt)
                    resp = s.recv(1024)
    #                print("resp:", resp, len(resp))
                    resp_seq = struct.unpack("<I", resp[:4])[0]
                    if resp_seq != last_seq:
                        continue
                    resp = resp[4:]
                    resp = decode_pkt(resp)
    #                print("decoded resp:", resp)
                    resp_op, resp_len, resp_off = struct.unpack("<HHI", resp[:8])
                    print("resp:", (resp_seq, resp_op, resp_len, resp_off))
                    if resp_off != offset or resp_len != len(chunk):
                        print("Invalid resp")
                        continue
                    break
                except socket.timeout:
                    print("timeout")
                    rexmit += 1
            offset += len(chunk)
        # Repeat few times to minimize chance of being lost
        for i in range(3):
            pkt = add_digest(struct.pack("<HHI", 0, 0, 0))
            s.send(pkt)
            time.sleep(0.1)

        print("Done, rexmits: %d" % rexmit)


cmd_parser = argparse.ArgumentParser(description="yaota8266 (yet another esp8266 OTA) client")
cmd_parser.add_argument("command", help="ota/sign/live-ota")
cmd_parser.add_argument("file", help="file to process")
cmd_parser.add_argument('-a', '--address', help="IP address of device to upgrade")
args = cmd_parser.parse_args()

if args.command in ("sign", "live-ota"):
    rsa_key = rsa_sign.load_key()

if args.command == "live-ota":
    live_ota()
else:
    cmd_parser.error("Unknown command")
