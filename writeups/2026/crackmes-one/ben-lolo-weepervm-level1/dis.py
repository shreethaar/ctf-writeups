import struct, sys

ELF = sys.argv[1] if len(sys.argv) > 1 else "WeeperVM--Level_1"

def sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3a)
    sh = lambda i: struct.unpack_from("<IIQQQQIIQQ", buf, e_shoff + i*e_shentsize)
    stroff = sh(e_shstrndx)[4]
    out = {}
    for i in range(e_shnum):
        n, _, _, _, off, size = sh(i)[:6]
        name = buf[stroff+n : buf.index(b"\0", stroff+n)].decode()
        out[name] = buf[off:off+size]
    return out

_S    = sections(open(ELF, "rb").read())
LOTUS = _S[".lotus"]
WORDS = list(struct.unpack("<%dI" % (len(_S[".weep"])//4), _S[".weep"]))

OPS = {0:'MOV',1:'LDI',2:'ADD',3:'SUB',4:'MUL',5:'MOD',6:'PUT',7:'READ',
       9:'CMP',10:'JMP',11:'AND',12:'OR',13:'XOR',14:'SHL',15:'SHR'}

def decode(raw):
    return (raw ^ (((raw >> 16) & 0xff) * 0x01010101)) & 0xffffffff

def src(mode, B): return {0: f'r{B}', 1: f'M[{B}]', 2: f'#{B}'}.get(mode, f'BAD{mode}')
def dst(mode, A): return f'M[{A}]' if mode else f'r{A}'

for pc, raw in enumerate(WORDS):
    if raw == 0:
        print(f'{pc:4d}: ---- HALT (raw=0)')
        continue
    w  = decode(raw)
    op, dm, sm = w >> 28, (w >> 27) & 1, (w >> 25) & 3
    A,  B      = (w >> 8) & 0xff, w & 0xff
    print(f'{pc:4d}: {raw:08x} -> {w:08x}  {OPS.get(op, f"BAD{op}"):5s} '
          f'{dst(dm, A):8s}, {src(sm, B)}')
