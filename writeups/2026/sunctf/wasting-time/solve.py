#!/usr/bin/env python3
# Wasting Time - SunCTF 2026
#
# The service accepts C source, compiles it, DELETES the .c file, then runs the
# binary 20 times. Each round it feeds a fresh random VM program on stdin and
# expects the binary to print orbit_vm(<its own source bytes>, ...). The source
# filter bans  #  ?  %  "  '  \  and caps the source at 3000 bytes -- so: a
# quine, with no preprocessor, no string/char literals, no printf and no %.
#
#   ./solve.py verify     # 200 randomised rounds against the reference VM
#   ./solve.py            # generate, then play the live instance
import math
import os
import subprocess
import sys

HOST, PORT = "wastingtime.chal.sunwaycybersecurityclub.org", 1337
MASK64 = 0xFFFFFFFFFFFFFFFF

# --------------------------------------------------------------------------
# Reference implementation, recovered from the PyArmor'd challenge.py.
# --------------------------------------------------------------------------

def rotate_left(value, amount):
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def random_u64():
    return int.from_bytes(os.urandom(8), "little")


def random_orbit(length):
    while True:
        step = random_u64() % (length - 1) + 1
        if math.gcd(step, length) == 1:
            return random_u64() % length, step


def make_program():
    n = 24 + random_u64() % 9
    ops = [0, 1, 2, 2, 3, 3, 4, 4, 5]
    while len(ops) < n:
        ops.append(random_u64() % 6)
    for i in range(len(ops) - 1, 0, -1):
        j = random_u64() % (i + 1)
        ops[i], ops[j] = ops[j], ops[i]
    prog = []
    for op in ops:
        k = random_u64()
        if op == 2:
            k |= 1                       # odd -> multiply is invertible
        elif op == 3:
            k = k % 63 + 1               # rotate amount in 1..63
        prog.append((op, k))
    return prog


def orbit_vm(source, pad, start, stride, seed, program):
    acc = seed ^ 0x9E3779B97F4A7C15
    idx = start
    for i, p in enumerate(pad):
        mixed = source[idx] ^ p
        acc ^= mixed + 1
        for op, k in program:
            if op == 0:
                acc ^= k
            elif op == 1:
                acc = (acc + k) & MASK64
            elif op == 2:
                acc = (acc * k) & MASK64
            elif op == 3:
                acc = rotate_left(acc, k)
            elif op == 4:
                acc ^= ((mixed + k + i) * 0x1385B9ED001AE395) & MASK64
            else:
                acc = (acc + (seed ^ k ^ i)) & MASK64
        idx += stride
        if idx >= len(source):
            idx -= len(source)
    return rotate_left(acc, 29) ^ 0x8F4577ED9F3F5715


def lines_are_valid(source):
    if not source.strip() or len(source.encode()) > 3000:
        return False
    try:
        source.encode("ascii")
    except UnicodeEncodeError:
        return False
    return not any(b in source for b in ("#", "?", "%", '"', "'", "\\"))


# --------------------------------------------------------------------------
# The quine.
#
# Layout:   long a[]={<NUMS>};<REST>
#
# a[] holds the source text with the <NUMS> run removed, packed 9 characters
# per element at 7 bits each (9*7 = 63 bits, fits a signed long). <NUMS> is the
# decimal rendering of a[], which the program can regenerate from the values it
# already holds -- that is what closes the self-reference.
#
# Per-byte decimal (`int a[]={108,111,...}`) costs ~3.4 chars of source per byte
# encoded and lands at 4160 bytes, over the 3000 cap. 7-bit packing costs ~2.2
# and lands at 2851.
# --------------------------------------------------------------------------
PREFIX = "long a[]={"
REST = "".join([
    "typedef unsigned long u;int getchar();int putchar();",
    "char s[3100],w[1100],b[24],o[40];int n,i,j,x,c,A;u m,t,q,d,e,g,y,k[40];",
    # decimal of v appended to s[]; no % anywhere, so v-v/10*10 is the modulo
    "void dc(u v){c=0;do b[c++]=48+(v-v/10*10),v=v/10;while(v);while(c)s[n++]=b[--c];}",
    "u rd(){u v=0,z=0;for(;z<64;z+=8)v|=(u)getchar()<<z;return v;}",
    "int main(){A=sizeof a/sizeof*a;",
    "for(i=0;i<A;i++)for(j=0;j<9;j++)w[i*9+j]=a[i]>>j*7&127;",   # unpack to w
    "for(i=0;i<10;i++)s[n++]=w[i];",                             # PREFIX
    "for(i=0;i<A;i++){if(i)s[n++]=44;dc(a[i]);}",                # <NUMS>
    "for(i=10;w[i];i++)s[n++]=w[i];",                            # "};"+REST
    "q=rd();d=rd();e=rd();g=rd();",                              # start,stride,seed,nprog
    "for(i=0;i<g;i++)o[i]=getchar(),k[i]=rd();",
    "m=e^0x9E3779B97F4A7C15;",
    "for(i=0;i<n;i++){t=s[q]^(u)getchar();m=m^t+1;",
    "for(j=0;j<g;j++){x=o[j];y=k[j];",
    "if(!x)m=m^y;",
    "else if(x==1)m=m+y;",
    "else if(x==2)m=m*y;",
    "else if(x==3)m=m<<y|m>>64-y;",
    "else if(x==4)m=m^(t+y+i)*0x1385B9ED001AE395;",
    "else m=m+(e^y^(u)i);}",
    "q=q+d;if(q>=n)q=q-n;}",
    "m=(m<<29|m>>35)^0x8F4577ED9F3F5715;",
    "n=0;dc(m);for(i=0;i<n;i++)putchar(s[i]);putchar(10);}",
    "\n"])


def build():
    T = PREFIX + "};" + REST
    Tp = T + "\0" * ((-len(T)) % 9)
    a = [sum(ord(Tp[i + j]) << (j * 7) for j in range(9)) for i in range(0, len(Tp), 9)]
    full = T[:len(PREFIX)] + ",".join(str(v) for v in a) + T[len(PREFIX):]
    assert lines_are_valid(full), "source would be rejected"
    assert "\n" not in full[:-1], "read_source() stops at the first blank line"
    return full


def verify(src, rounds=200):
    open("sol.c", "w", newline="\n").write(src)
    subprocess.check_call(["gcc", "-std=gnu11", "-O0", "-w", "-o", "sol", "sol.c"])
    raw = src.encode()
    for r in range(rounds):
        start, step = random_orbit(len(raw))
        seed, prog = random_u64(), make_program()
        noise = os.urandom(len(raw))
        stdin = b"".join(v.to_bytes(8, "little") for v in (start, step, seed, len(prog)))
        stdin += b"".join(bytes([op]) + k.to_bytes(8, "little") for op, k in prog)
        got = int(subprocess.check_output(["./sol"], input=stdin + noise, timeout=5))
        want = orbit_vm(raw, noise, start, step, seed, prog)
        if got != want:
            sys.exit("[!] round %d mismatch: %d != %d" % (r, got, want))
    print("[+] %d/%d rounds match" % (rounds, rounds))


src = build()
print("[*] source is %d bytes (cap 3000)" % len(src))
if len(sys.argv) > 1 and sys.argv[1] == "verify":
    verify(src)
    sys.exit(0)

from pwn import remote                                    # noqa: E402

io = remote(HOST, PORT)
io.recvuntil(b"blank line:")
io.sendline(src.strip().encode())                         # the whole program, one line
io.sendline(b"")                                          # blank line ends read_source()
print(io.recvall(timeout=180).decode(errors="replace"))
