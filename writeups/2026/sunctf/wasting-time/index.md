# Wasting Time

- Category: misc

"Hope I could waste your time. Good luck."

Filed under misc, but it is two challenges stacked: unwrap a PyArmor'd service to learn what it checks, then write a C quine under a blacklist that removes the preprocessor, string literals and `printf` at once.

### Solution:

##### 1. First contact rejects everything

```
$ nc wastingtime.chal.sunwaycybersecurityclub.org 1337
C source, end with a blank line:
#include <stdio.h>
int main(){ printf("hello\n"); return 0; }

Rejected source
```

The handout is `challenge.py` — PyArmor 9.2.6 (trial), four lines wrapping a 42 KB blob. Guessing the filter from outside is the time-wasting path the title advertises.

##### 2. `sys.settrace` walks straight through PyArmor

The blob header is `PY000000 \x00\x03\x0b` — CPython 3.11 code objects, so the module only imports under 3.11 (`uv python install 3.11`). It imports cleanly, and module-level constants are already plaintext:

```python
>>> import challenge as c
>>> c.BANNED, c.MAX_SOURCE, c.ROUNDS
(('#', '?', '%', '"', "'", '\\'), 3000, 20)
```

Function bodies are not. PyArmor 9 keeps real `function` objects and encrypts only `co_code`, decrypting in place on frame entry and re-encrypting on exit — that is what the `C_ENTER_CO_OBJECT_INDEX` / `C_LEAVE_CO_OBJECT_INDEX` builtins bracketing every body do. `f.__code__.co_code` from outside is ciphertext; `frame.f_code.co_code` from *inside* a live frame is not, and the runtime never blocks `sys.settrace`. That is the whole tool:

```python
def tr(frame, event, arg):
    co = frame.f_code
    if "challenge" in co.co_filename:
        codes[(co.co_name, co.co_firstlineno)] = (co, co.co_code)   # decrypted here
    return tr

sys.settrace(tr)
c.main()                    # every function that runs gets dumped
sys.settrace(None)
```

`co.replace(co_code=...)` glues the plaintext back onto the otherwise-intact code object for `dis`. `orbit_vm` and `rotate_left` only run after a round verifies, so they get called directly instead of reached through `main`. Full tool: [unarmor.py](unarmor.py).

##### 3. What the service is really asking for

`main` writes the source to a temp `.c`, compiles it, and then **deletes it** before any round runs:

```python
proc = subprocess.run(["gcc", "-std=gnu11", "-O0", "-w", "-o", binpath, cpath], ...)
os.remove(cpath)                       # the .c is gone before the binary ever runs
for rnd in range(1, ROUNDS + 1):
    start, step = random_orbit(len(src_bytes))
    seed, prog  = random_u64(), make_program()
    noise       = os.urandom(len(src_bytes))
    out = subprocess.check_output([binpath], input=header + progblob + noise, timeout=5)
    if int(out.strip()) != orbit_vm(src_bytes, noise, start, step, seed, prog):
        fail("Verification failed")
```

Each of the 20 rounds pipes in a 32-byte header (`start`, `stride`, `seed`, `nprog` as LE u64s), `nprog` instructions of `[u8 op][u64 k]`, then `len(source)` pad bytes, and wants one decimal integer back:

```python
def orbit_vm(source, pad, start, stride, seed, program):
    acc = seed ^ 0x9E3779B97F4A7C15
    idx = start
    for i, p in enumerate(pad):
        mixed = source[idx] ^ p                       # <-- source[], byte by byte
        acc ^= mixed + 1
        for op, k in program:
            if   op == 0: acc ^= k
            elif op == 1: acc = (acc + k) & MASK64
            elif op == 2: acc = (acc * k) & MASK64
            elif op == 3: acc = rotate_left(acc, k)
            elif op == 4: acc ^= ((mixed + k + i) * 0x1385B9ED001AE395) & MASK64
            else:         acc = (acc + (seed ^ k ^ i)) & MASK64
        idx += stride
        if idx >= len(source):
            idx -= len(source)
    return rotate_left(acc, 29) ^ 0x8F4577ED9F3F5715
```

`random_orbit` picks a `stride` coprime to `len(source)`, so the walk hits every index exactly once — partial knowledge of the source is worth nothing. The VM is noise. The statement is that the binary must reproduce its own source byte for byte, from memory, after the file is gone: a quine. `BANNED = # ? % " ' \` decides what kind — no preprocessor, no literals, and no `%`, which takes `printf` and the modulo with it, inside `MAX_SOURCE = 3000` bytes.

##### 4. Budgeting the encoding

With no string literals the source carries itself as an integer array: `long a[]={<NUMS>};<REST>`, where `a[]` encodes everything *except* the `<NUMS>` run, and `<NUMS>` is regenerated at runtime by printing `a[]` back out in decimal. That closes the self-reference — the array's textual form is derivable from its own values.

Total size is `|T| * (1 + r)` for code text `T` and chars-of-`<NUMS>` per char of `T`:

| encoding | element holds | cost | r | total |
|---|---|---|---|---|
| `int a[]={108,111,...}` | 1 char | ~3.4 per char | 3.40 | **4160** |
| 8 chars x 8 bits | 8 chars | 20 per 8 | 2.50 | **3187** |
| 9 chars x 7 bits | 9 chars | 20 per 9 | 2.22 | **2851** |

The middle row is the trap. A full 64-bit word feels like the dense option, but the top byte of an ASCII pack is 32..126, so every element is ~1.8e19 — 19 or 20 digits either way. Cost is per element, so the win is more *characters* per element, not more bits. Seven bits each fits 9 chars in 63 bits, still inside a signed `long`.

##### 5. The program

2851 bytes, one line, no banned characters. Expanded for reading:

```c
long a[]={4448271145916676076,7334560076886114043,...,99 elements};
typedef unsigned long u;
int getchar();int putchar();
char s[3100],w[1100],b[24],o[40];
int n,i,j,x,c,A;
u m,t,q,d,e,g,y,k[40];
void dc(u v){c=0;do b[c++]=48+(v-v/10*10),v=v/10;while(v);while(c)s[n++]=b[--c];}
u rd(){u v=0,z=0;for(;z<64;z+=8)v|=(u)getchar()<<z;return v;}
int main(){
  A=sizeof a/sizeof*a;
  for(i=0;i<A;i++)for(j=0;j<9;j++)w[i*9+j]=a[i]>>j*7&127;   /* unpack T into w */
  for(i=0;i<10;i++)s[n++]=w[i];                             /* "long a[]={"    */
  for(i=0;i<A;i++){if(i)s[n++]=44;dc(a[i]);}                /* <NUMS>          */
  for(i=10;w[i];i++)s[n++]=w[i];                            /* "};" + the rest */
  q=rd();d=rd();e=rd();g=rd();                              /* start,stride,seed,nprog */
  for(i=0;i<g;i++)o[i]=getchar(),k[i]=rd();
  m=e^0x9E3779B97F4A7C15;
  for(i=0;i<n;i++){t=s[q]^(u)getchar();m=m^t+1;
    for(j=0;j<g;j++){x=o[j];y=k[j];
      if(!x)m=m^y;
      else if(x==1)m=m+y;
      else if(x==2)m=m*y;
      else if(x==3)m=m<<y|m>>64-y;
      else if(x==4)m=m^(t+y+i)*0x1385B9ED001AE395;
      else m=m+(e^y^(u)i);}
    q=q+d;if(q>=n)q=q-n;}
  m=(m<<29|m>>35)^0x8F4577ED9F3F5715;
  n=0;dc(m);for(i=0;i<n;i++)putchar(s[i]);putchar(10);
}
```

- `dc` is the missing `printf`: `v-v/10*10` for the modulo, digits into `s[]`. It builds `<NUMS>`, then runs once more with `n` reset to 0 — the routine that writes the quine writes the answer. The orbit wrap needs no modulo either, since `stride < len`.
- `int getchar();int putchar();` by hand: GCC 14 makes an implicit declaration a hard error, and `-w` suppresses warnings, not errors.
- `T` has no NUL and the pack is zero-padded, so `for(i=10;w[i];i++)` self-terminates.
- `^` binds looser than `|`: without the parens `m=(m<<29|m>>35)^K` silently becomes `m<<29|(m>>35^K)`. `m^t+1` is *correctly* `m^(t+1)`, since `+` binds tighter.

##### 6. Verify offline, then spend one connection

Twenty consecutive rounds behind a `fail()` that closes the socket means every guess costs a reconnect, so the recovered VM doubles as an oracle. `./solve.py verify` runs 200 randomised rounds against it, then the real obfuscated `challenge.py` under 3.11 checks what the oracle cannot — `lines_are_valid` and `gcc`:

```
[+] 200/200 rounds match

$ (cat sol.c; echo) | python3.11 -c 'import challenge; challenge.main()'
round 01: ok ... round 20: ok
All copies match. sunway26{local_test_flag}      <- FLAG env var, placeholder default
```

Remote, on the first connection:

```
round 01: ok
...
round 20: ok
All copies match. sunway26{c0pycat_n3v3r_f0rg3ts_3v3ry_s1ngl3_byt3_1t_3v3r_wr0t3}
```

Note the prefix: the challenge text promises `sunctf26{...}`, but this service emits `sunway26{...}`, unlike the rest of the CTF. Submit what the socket says.

Full script: [solve.py](solve.py)

**Flag:** `sunway26{c0pycat_n3v3r_f0rg3ts_3v3ry_s1ngl3_byt3_1t_3v3r_wr0t3}`

### Takeaways

- PyArmor 8/9 decrypt `co_code` on frame entry, so the plaintext exists only while a frame is live — and `sys.settrace` runs inside that window unblocked. A nine-line trace function plus `co.replace(co_code=...)` gets full disassembly with no unpacker, no debugger, no patched interpreter. Match the interpreter to the blob's magic first.
- A character blacklist is a spec, not an obstacle to route around: read the banned set as a list of things to reimplement.
- Packing into printed decimal costs per *element* (~20 chars for anything near 64 bits), not per bit. Fit the most characters per element, not the most bits — worth 10% of the budget here.
- A challenge that deletes your source after compiling and then asks about its bytes wants a quine, whatever the category says. The tell is a checker walking `source[]` with a stride coprime to the length: coprime means full coverage, so no partial-knowledge shortcut exists.
