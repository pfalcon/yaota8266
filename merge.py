import sys


last_sz = 0

def align(f):
    global last_sz
    if last_sz & 0xfff:
        f.write(b"\xff" * (0x1000 - (last_sz & 0xfff)))

assert sys.argv[1] == "-o"
fout = open(sys.argv[2], "wb")


for fname in sys.argv[3:]:
    align(fout)
    last_sz = 0
    with open(fname, "rb") as fin:
        while True:
            buf = fin.read(4096)
            if not buf:
                break
            fout.write(buf)
            last_sz += len(buf)

align(fout)
fout.close()
