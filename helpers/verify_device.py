
"""
    Verify if yaota8266.bin flashed on the device
    and check if the same RSA key was used

    Just call this file on your ESP8266.
    Insert your RSA modulus, first!
"""
import esp
from micropython import const

YAOTA8266_MAGIC = b'yaotaota'  # for: machine.RTC().memory('yaotaota') to trigger OTA

# copy&paste your RSA modulus from your config.h:
YAOTA8266_RSA_MODULUS = b'\xce\x4a\xaf\x65\x0d\x4a\x74\xda\xc1\x30\x59\x80\xcf\xdd\xe8\x2a\x2e\x1d\xf7\xa8\xc9\x6c\xa9\x4a\x2c\xb7\x8a\x5a\x2a\x25\xc0\x2b\x7b\x2f\x58\x4c\xa8\xcb\x82\x07\x06\x08\x7e\xff\x1f\xce\x47\x13\x67\x94\x5f\x9a\xac\x5e\x7d\xcf\x63\xf0\x08\xe9\x51\x98\x95\x01'

CHUNK_SIZE = const(128)
BUFFER = bytearray(CHUNK_SIZE)


def search(offset, text, max_address=None):
    offset_step = CHUNK_SIZE - len(text)

    if offset_step <= 0:
        raise AssertionError('Search text too large: increase CHUNK_SIZE!')

    if max_address is None:
        max_address = esp.flash_size()

    end_researched = False
    while True:
        if offset + CHUNK_SIZE > max_address:
            # Search to esp.max_address(), but don't go beyond.
            offset = max_address - CHUNK_SIZE
            end_researched = True

        try:
            esp.flash_read(offset, BUFFER)
        except OSError as e:
            print('Read flash error: %s at 0x%x - 0x%x' % (e, offset, offset + CHUNK_SIZE))
            return -1

        if text in BUFFER:
            # bytearray has no .find() method
            return offset + bytes(BUFFER).find(text)

        if end_researched:
            print('End researched, searched up to 0x%x' % (offset + CHUNK_SIZE))
            return -1

        offset += offset_step


def verfiy_yaota8266():
    pos = search(offset=0, text=YAOTA8266_MAGIC, max_address=0x100)
    if pos == -1:
        print('yaota8266 magic word not found!')
    else:
        print('yaota8266 magic word found at 0x%x, ok.' % pos)

    pos = search(offset=0, text=YAOTA8266_RSA_MODULUS, max_address=0x3c000)
    if pos == -1:
        print('yaota8266 RSA modulus not found! Maybe compiles with other RSA key?!?')
    else:
        print('yaota8266 RSA modulus found at 0x%x, ok.' % pos)


if __name__ == '__main__':
    verfiy_yaota8266()
