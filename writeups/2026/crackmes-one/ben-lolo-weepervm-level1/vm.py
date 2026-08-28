"""weep-VM emulator.  usage: python3 vm.py <binary> <input-string>"""
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

def dec(raw):
    return (raw ^ (((raw >> 16) & 0xff) * 0x01010101)) & 0xffffffff

M32 = 0xffffffff
def s32(v): 
    v &= M32
    return v - (1<<32) if v & 0x80000000 else v

class VM:
    def __init__(self, inp=b'', trace=False):
        self.M = bytearray(LOTUS)
        self.R = [0]*16
        self.F = 0
        self.pc = 0
        self.inp = bytearray(inp)
        self.ip = 0
        self.out = bytearray()
        self.trace = trace
        self.log = []
        self.steps = 0

    def rd(self):
        if self.ip < len(self.inp):
            c = self.inp[self.ip]; self.ip += 1; return c
        return None

    # memory helpers
    def m8(self, a): return self.M[a & 0xff]
    def m32(self, a):
        a &= 0xff
        return int.from_bytes(bytes(self.M[i & 0xff] for i in range(a, a+4)), 'little')
    def wm32(self, a, v):
        a &= 0xff; v &= M32
        for i in range(4): self.M[(a+i) & 0xff] = (v >> (8*i)) & 0xff

    def srcval(self, sm, B, width=32):
        if sm == 0: return self.R[B & 0xf]
        if sm == 1: return self.m8(B) if width == 8 else self.m32(B)
        if sm == 2: return B
        raise ValueError('bad src mode')

    def step(self):
        raw = WORDS[self.pc]
        if raw == 0: return False
        w = dec(raw)
        op = w >> 28; dm = (w>>27)&1; sm = (w>>25)&3
        A = (w>>8)&0xff; B = w&0xff
        pc0 = self.pc

        if op == 0:      # MOV
            v = self.srcval(sm, B, 8 if sm==1 else 32)
            if dm: self.wm32(A, v)
            else:  self.R[A & 0xf] = v & M32
        elif op == 1:    # LDI / STI
            if dm:
                v = self.m8(B) if sm==1 else (B if sm==2 else self.R[B & 0xf] & 0xff)
                self.M[self.m8(A)] = v & 0xff
            else:
                v = self.m8(B) if sm==1 else (B if sm==2 else self.R[B & 0xf])
                self.R[A & 0xf] = self.m8(v)
        elif op in (2,3,4):   # ADD SUB MUL
            v = self.srcval(sm, B, 32)
            cur = s32(self.m32(A)) if dm else s32(self.R[A & 0xf])
            v = s32(v)
            r = cur + v if op==2 else (cur - v if op==3 else cur*v)
            if dm: self.wm32(A, r)
            else:  self.R[A & 0xf] = r & M32
        elif op == 5:    # MOD (unsigned)
            cur = self.m32(A) if dm else self.R[A & 0xf]
            v = self.srcval(sm, B, 32)
            r = cur % v if v else 0
            if dm: self.wm32(A, r)
            else:  self.R[A & 0xf] = r & M32
        elif op == 6:    # PUT
            ch = self.m8(A) if dm else (self.R[A & 0xf] & 0xff)
            cnt = self.srcval(sm, B, 8 if sm==1 else 32)
            self.out += bytes([ch]) * s32(cnt) if s32(cnt) > 0 else b''
        elif op == 7:    # READ
            cnt = self.srcval(sm, B, 8 if sm==1 else 32)
            i = 0
            while i < s32(cnt):
                c = self.rd()
                if c is None: c = 0x0a
                self.M[(A+i) & 0xff] = c
                if c == 0x0a: break
                i += 1
            if s32(cnt) == i:
                tot = 0
                while True:
                    c = self.rd()
                    if c is None: tot += 1; break
                    tot += 1
                    if c == 0x0a: break
                if tot != 1: self.F |= 0x20
        elif op == 9:    # CMP
            a = self.m8(A) if dm else self.R[A & 0xf]
            b = self.srcval(sm, B, 8 if sm==1 else 32)
            base = 0x60 if (self.F & 0x20) else 0x40
            self.F = base | (1 if a==b else (2 if b < a else 4))
        elif op == 10:   # JMP
            tgt = self.m8(A) if dm else self.R[A & 0xf]
            mask = self.srcval(sm, B, 8 if sm==1 else 32)
            if self.F & mask:
                self.pc = (tgt - 1) & M32
        elif op in (11,12,13):  # AND OR XOR
            v = self.srcval(sm, B, 32)
            cur = self.m32(A) if dm else self.R[A & 0xf]
            r = cur & v if op==11 else (cur | v if op==12 else cur ^ v)
            if dm: self.wm32(A, r)
            else:  self.R[A & 0xf] = r & M32
        elif op in (14,15):    # SHL SHR
            v = self.srcval(sm, B, 32) & 0x1f
            cur = self.m32(A) if dm else self.R[A & 0xf]
            r = (s32(cur) << v) if op==14 else (cur >> v)
            if dm: self.wm32(A, r)
            else:  self.R[A & 0xf] = r & M32
        else:
            raise ValueError(f'bad opcode {op} at {pc0}')

        if self.trace and op != 6:
            self.log.append((pc0, op, dm, sm, A, B, list(self.R), self.F))
        self.pc = (self.pc + 1) & M32
        self.steps += 1
        return True

    def run(self, maxsteps=5_000_000):
        while self.steps < maxsteps:
            if not self.step(): return 'HALT'
            if self.pc >= len(WORDS): return 'OOB'
        return 'MAXSTEPS'

if __name__ == '__main__':
    inp = (sys.argv[2].encode() if len(sys.argv) > 2 else b'test') + b'\n'
    vm = VM(inp)
    r = vm.run()
    sys.stdout.buffer.write(vm.out)
    print(f"\n[{r} steps={vm.steps} pc={vm.pc}]")
