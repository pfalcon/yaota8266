
"""
    Verify if yaota8266.bin flashed on the device
    and check if the same RSA key was used

    Just call this file on your ESP8266.
    Insert your RSA modulus, first!
"""

import esp

YAOTA8266_MAGIC = b'yaotaota'  # for: machine.RTC().memory('yaotaota') to trigger OTA

# copy&paste your RSA modulus from your config.h:
YAOTA8266_RSA_MODULUS = b'\xce\x4a\xaf\x65\x0d\x4a\x74\xda\xc1\x30\x59\x80\xcf\xdd\xe8\x2a\x2e\x1d\xf7\xa8\xc9\x6c\xa9\x4a\x2c\xb7\x8a\x5a\x2a\x25\xc0\x2b\x7b\x2f\x58\x4c\xa8\xcb\x82\x07\x06\x08\x7e\xff\x1f\xce\x47\x13\x67\x94\x5f\x9a\xac\x5e\x7d\xcf\x63\xf0\x08\xe9\x51\x98\x95\x01'


def verfiy_yaota8266():
    # Read the first 4KB RAM into buffer
    # https://forum.micropython.org/viewtopic.php?f=16&t=7467&p=42871#p42871
    buffer = bytearray(4096)
    esp.flash_read(0, buffer)

    buffer = bytes(buffer)  # bytearray has no .find() method
    pos = buffer.find(YAOTA8266_MAGIC)
    if pos == -1:
        print('yaota8266 magic word not found!')
    else:
        print('yaota8266 magic word found at 0x%x, ok.' % pos)

    pos = buffer.find(YAOTA8266_RSA_MODULUS)
    if pos == -1:
        print('yaota8266 RSA modulus not found! Maybe compiles with other RSA key?!?')
    else:
        print('yaota8266 RSA modulus found at 0x%x, ok.' % pos)


if __name__ == '__main__':
    verfiy_yaota8266()
