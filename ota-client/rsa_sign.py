import os
from binascii import hexlify, unhexlify


def load_key():
    comps = {}

    for l in os.popen("openssl pkey -in priv.key -text", "r"):
        l = l.rstrip()
        if l[0] != " " and l[-1] == ":":
            last_comp = l[:-1]
        elif l.startswith("    "):
            comps[last_comp] = comps.get(last_comp, "") + l.lstrip()

    print(comps)
    return comps


def dump_c(comps):
    print('mod = "%s"' % comps["modulus"][2:].replace(":", "\\x"))
    print('pe = "%s"' % comps["privateExponent"][2:].replace(":", "\\x"))


def sign(comps, to_sign):
    mod = comps["modulus"]
    assert mod.startswith("00:")
    mod = mod[3:].replace(":", "")
    BITS = len(mod) // 2 * 8
#    print("Key bits:", BITS)

    mod = int.from_bytes(unhexlify(mod), "big")
    pe = int.from_bytes(unhexlify(comps["privateExponent"].replace(":", "")), "big")

    pad_len = BITS // 8 - len(to_sign) - 3
#    print("Pad length:", pad_len)
    assert pad_len >= 8

    buf = b"\0\x01" + (b"\xff" * pad_len) + b"\0" + to_sign
#    print("Padded to-sign len:", len(buf))
    val = int.from_bytes(buf, "big")
#    print("Padded to-sign:", val, hex(val))

    sig = pow(val, pe, mod)
#    print("Sig (int):", sig, hex(sig))
    sig_b = sig.to_bytes(BITS // 8, "big")
#    print(hexlify(sig_b))
    return sig_b


if __name__ == "__main__":
    comps = load_key()
    sign(comps, b"foob\0")
