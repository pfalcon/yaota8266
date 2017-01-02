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
rexmit = 0


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


def make_pkt(offset, data):
    pkt = struct.pack("<HHI", 0, len(data), offset) + data
    pkt = add_digest(pkt)
    return pkt


def decode_pkt(pkt):
    global last_aes_key
    aes = AES.new(last_aes_key, AES.MODE_CBC, AES_IV)
    return aes.decrypt(pkt)


def send_recv(s, pkt):
    global rexmit

    while True:
        try:
            print("Sending #%d" % last_seq)
            s.send(pkt)
            resp = s.recv(1024)
            #print("resp:", resp, len(resp))
            resp_seq = struct.unpack("<I", resp[:4])[0]
            if resp_seq != last_seq:
                continue
            resp = resp[4:]
            resp = decode_pkt(resp)
            #print("decoded resp:", resp)
            resp_op, resp_len, resp_off = struct.unpack("<HHI", resp[:8])
            print("resp:", (resp_seq, resp_op, resp_len, resp_off))
            if resp_off != offset or resp_len != len(chunk):
                print("Invalid resp")
                continue
            break
        except socket.timeout:
            print("timeout")
            rexmit += 1

def send_ota_end(s):
    # Repeat few times to minimize chance of being lost
    for i in range(3):
        pkt = add_digest(struct.pack("<HHI", 0, 0, 0))
        s.send(pkt)
        time.sleep(0.1)

def live_ota():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((args.address, 8266))
    s.settimeout(0.3)

    offset = 0
    with open(args.file, "rb") as f:
        while True:
            chunk = f.read(BLK_SIZE)
            if not chunk:
                break
            pkt = make_pkt(offset, chunk)
            #print("pkt:", pkt)
            send_recv(s, pkt)
            offset += len(chunk)

    send_ota_end(s)
    print("Done, rexmits: %d" % rexmit)


def make_ota():

    def hash_write(data):
        hasher.update(data)
        f_out.write(data)

    offset = 0
    with open(args.file, "rb") as f_in, open(args.file + ".ota", "wb") as f_out:
        hasher = hashlib.sha1()
        hash_write(b"yaota8266\x01")
        while True:
            chunk = f_in.read(BLK_SIZE)
            if not chunk:
                break
            pkt = make_pkt(offset, chunk)
            hash_write(struct.pack("<H", len(pkt)))
            hash_write(pkt)
            offset += len(chunk)
        f_out.write(struct.pack("<H", 0))
        f_out.write(hasher.digest())


def validate_ota(fname):
    with open(fname, "rb") as f_in:
        hasher = hashlib.sha1()
        sig = f_in.read(10)
        if sig != b"yaota8266\x01":
            cmd_parser.error("Invalid OTA file signature")
        hasher.update(sig)
        while True:
            data = f_in.read(2)
            sz = struct.unpack("<H", data)[0]
            if not sz:
                break
            hasher.update(data)
            data = f_in.read(sz)
            hasher.update(data)
        hash = f_in.read(20)
        if hash != hasher.digest():
            cmd_parser.error("Invalid OTA file checksum, file corrupted")


def canned_ota(fname):
    validate_ota(fname)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((args.address, 8266))
    s.settimeout(0.3)

    with open(fname, "rb") as f_in:
        # Skip signature
        sig = f_in.read(10)
        while True:
            data = f_in.read(2)
            sz = struct.unpack("<H", data)[0]
            if not sz:
                break
            data = f_in.read(sz)
            send_recv(s, data)

    send_ota_end(s)
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
elif args.command == "sign":
    make_ota()
elif args.command == "ota":
    canned_ota(args.file)
else:
    cmd_parser.error("Unknown command")
