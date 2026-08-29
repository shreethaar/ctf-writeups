---
title: "Schizo"
layout: default
---

# Schizo

unemployed crackme

- Category: rev
- Difficulty: 3.0
- Challenge author: S3c_Cult
- Challenge link: [crackmes.one](https://crackmes.one/crackme/698f40f1e2ba6023bfacaa82)
- Language: C/C++ — the challenge page says **Go**, which is the first lie of several
- Platform: Linux x86-64 (ELF PIE, dynamically linked against OpenSSL)

There is no flag format given. The name is the entire hint: every piece of metadata the binary offers about itself contradicts every other piece, and none of it is true. The description claims Go, the symbol table claims Rust, the section table claims both, and the imports say plain C++. None of that misdirection is load-bearing — the real challenge is a three-stage unwrap (self-derived AES key → dropped shared library → a home-made block cipher) sitting behind a flag that never exists in the binary at all, because it arrives over HTTP.

### Solution:

##### 1. Every claim the file makes about itself is false

The drop is a binary, an opaque `lib.so`, and a stub HTTP server.

```bash
$ file schizo lib.so
schizo: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
        interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, not stripped
lib.so: data
```

`lib.so` is not a library — 99584 bytes at 7.998 bits/byte entropy over all 256 values, i.e. ciphertext, and a multiple of 16. "not stripped" on `schizo` is also bait:

```bash
$ nm schizo | wc -l
1
$ nm schizo
0000000000009171 t rust_panic
```

One planted symbol, named to suggest Rust, and enough to make `file` report a symbol table. The section headers keep the joke going:

```bash
$ readelf -SW schizo | sed -n '15,22p'
  [15] .sforce2          PROGBITS  00000000000b7d10 0b7d10 0003c6 00  AX
  [16] .gosymtab         PROGBITS  00000000000b80d6 0b80d6 000007 00  AX
  [17] .gopclntab        PROGBITS  00000000000b80dd 0b80dd 000007 00  AX
  [18] .go.buildinfo     PROGBITS  00000000000b80e4 0b80e4 000007 00  AX
  [19] .note.go.buildid  PROGBITS  00000000000b80eb 0b80eb 000007 00  AX
  [20] borland.resspare  PROGBITS  00000000000b80f2 0b80f2 000007 00  AX
  [21] .HP.init          PROGBITS  00000000000b80f9 0b80f9 000007 00  AX
```

Four fake Go markers, one fake Borland and one fake HP section, seven bytes each. The odd one out is `.sforce2` — 966 bytes, executable, and the only one with real content. Remember it.

What the binary actually *is* shows up in the imports, which no amount of section forgery can hide: `EVP_aes_256_cbc`, `EVP_DecryptInit_ex`/`Update`/`Final_ex`, `SHA256`, `mkstemp`, `fchmod`, `dlopen`, `dlsym`, `unlink`, `ptrace`, `socket`/`connect`/`getaddrinfo`, and a wall of `std::` / `__cxa_*`. That is a C++ program that decrypts something, drops it, loads it, deletes it, and talks to the network.

Since the symbol table is a decoy, `main` comes from the entry stub:

```asm
8c58:  lea    rdi,[rip+0x1d63]        # a9c2  <- main
8c5f:  call   QWORD PTR [rip+0xfb373] # __libc_start_main
```

##### 2. `main` is the whole program in forty lines

Decompiling `0xa9c2` lays out the entire structure:

```c
sub_8e7b(v5);                                    // build key material
sub_1361c(v7, "lib.so", v6);
sub_2894f(v8, v7, v5);                           // AES-decrypt lib.so
v15 = sub_8d3a(v8, &v9);                         // drop + dlopen
if (v15) {
  dat_1046d0 = dlsym(v15, "___1");
  dat_1046d8 = dlsym(v15, "___3");
  dat_1046e0 = dlsym(v15, "___4");
  sub_1361c(v10, "`\\wiXh4s:%Vs:DKsIa<w_U^Wvk\"7)fCzW,%XD6.<:8C:vk$dprRu@;^tW7", v6);
  sub_941d(v11, v10);                            // decode
  (*dat_1046e0)(v7, v11);                        // ___4 -> plaintext
  std::ostream::operator<<(std::operator<<(_ZSt4cout, v7), dat_103fc0);
  for (v13 = 0; v13 < sub_31902(0x104610); v13++) {
    ...
    v14 = sub_3dada(sub_3da74(v6, 0));           // index
    sub_3db0c(v10, sub_3da74(v6, 1));            // payload
    sub_9653(v11, v7);                           // <- fetch
    sub_2ff88(sub_33c78(0x104650, v14), v11);    // store at index
  }
  sub_a286();                                    // verdict
  dlclose(v15); close(v9);
}
```

Three globals matter: `0x104610`, `0x104630` and `0x104650`, all in `.bss`.

##### 3. The AES key is the binary's own code

`sub_8e7b` never touches a hardcoded key. It re-opens itself and reads a section out of its own image:

```c
v4 = open("/proc/self/exe", 0);
fstat(v4, v7);
v5 = mmap(0, v12, 1, 2, v4, 0);
v2 = *(long *)(v5 + 0x28);                       // e_shoff
v3 = *(long *)(v5 + *(u16 *)(v5 + 0x3e) * 0x40 + v2 + 0x18);   // shstrtab
while (...) {
  v1 = *(u32 *)(v5 + v9 * 0x40 + v2);
  if (!strcmp(v5 + v1 + v3, ".sforce2")) break;  // find .sforce2
  v9 += 1;
}
for (v10 = 0; v10 < <sh_size>; v10++) {
  sub_3d23c(v8, 6, "{:02x}", v5 + v10 + v3);     // hex-encode each byte
  sub_30c84(a0, v8);
}
```

So the key material is the **lowercase hex dump of `.sforce2`'s 966 bytes** — 1932 characters. `sub_2894f` then hashes it and decrypts:

```c
sub_287fe(&v10, a2);                             // SHA256(key material) -> 32 bytes
v13 = EVP_CIPHER_CTX_new();
EVP_DecryptInit_ex(v13, EVP_aes_256_cbc(), 0, sub_28902(&v10), sub_3c720(0x104670));
```

with `sub_287fe` being a one-liner around `SHA256(...)`. The IV global is built by the static constructor at `sub_b06f` from `.rodata`:

```c
sub_28148(0x104670, 0xc0290, 0x10, &v1);         // 16 bytes at 0xc0290
sub_2bc2a(0x104610, 0x102d60, 0x102d88, &v1);    // 5 const char*
sub_2bc2a(0x104630, 0x102da0, 0x102dc8, &v1);    // 5 const char*
sub_2bc2a(0x104650, 0x102de0, 0x102e08, &v1);    // 5 empty strings
```

```bash
$ dd if=schizo bs=1 skip=$((0xc0290)) count=16 2>/dev/null | xxd
00000000: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  ................
```

`key = SHA256(hex(.sforce2))`, `iv = 00 01 .. 0f`, AES-256-CBC. Because `.sforce2` is *executable code that the program runs*, this doubles as an integrity check: patch a single byte anywhere in it and the key changes and `lib.so` will not decrypt.

```python
sec = exe[0xb7d10:0xb7d10 + 0x3c6]
key = hashlib.sha256(''.join('%02x' % b for b in sec).encode()).digest()
# 098a5c8aebbe8a087e10f4a0a60b9238f41b5566be57068101f5cfd903d9c6f5
pt = AES.new(key, AES.MODE_CBC, bytes(range(16))).decrypt(open('lib.so','rb').read())
pt = pt[:-pt[-1]]                                # PKCS#7, 8 bytes
```

```bash
$ file lib_dec.so
lib_dec.so: ELF 64-bit LSB shared object, x86-64, dynamically linked, not stripped
```

And this one really is not stripped:

```bash
$ nm -C lib_dec.so | grep -E ' [TtWw] ' | grep -v 'std::\|__gnu\|_GLOBAL'
00000000000093cd T ___1
0000000000009c2d T ___3
0000000000009cf4 T ___4
0000000000009dc0 T to_hex(...)
0000000000008edb t xorshift32(unsigned int&)
0000000000008e59 t rotate_left(unsigned char, int)
0000000000008e9a t rotate_right(unsigned char, int)
0000000000009085 t build_permutation_sequence(unsigned int, int, unsigned long)
0000000000008f30 t prng_byte(unsigned int&)
```

The loader itself (`sub_8d3a`) is unsubtle about its intentions:

```c
builtin_strncpy(v4, "/tmp/.trojanXXXXXX", 0x13);
v1 = mkstemp(v4);
write(v1, sub_3c720(a0), sub_28926(a0));
fchmod(v1, 0x140);                               // 0500
v3 = dlopen(v4, 2);
unlink(v4);                                      // gone before it is even used
```

##### 4. Two stacked string layers

Every literal in the binary goes through `sub_941d` and then `___4`. `sub_941d` wraps `sub_afebb`, which is a codec worth reading carefully because it is *not* ascii85 — the radix is `0x5b`:

```c
while (v2 = v4 + -1, v4) {
  if (v6 != 0xffffffff) {
    v5 += 0xd;                                                   // 13 bits per pair
    v7 |= ((*v8 - 0x21) + v6 * 0x5b) << (0x20 - v5 & 0x1f);      // radix 91
    do { *(v9 + a2) = v7 >> 0x18; v7 <<= 8; v5 -= 8; v9++; } while (8 <= v5);
    v6 = 0xffffffff;
  } else {
    v6 = *v8 - 0x21;                                             // digit = c - '!'
  }
  v8 = v1;
}
```

Two characters, digit value `c - 0x21`, radix 91, packed as 13 bits MSB-first — a fixed-width basE91 variant. Mistaking it for ascii85 costs you an afternoon: base-85 decodes the first pair of every string to something three off the right answer, which looks like an off-by-one rather than a wrong radix.

`___4` is the second layer, and `___3` in the library is its inverse, which is how you confirm the direction:

```c
// ___4 (decrypt)                      // ___3 (encrypt)
v1 = rotate_right(~(s[i] - (i + (i<<3))), 3);
                                       v1 = rotate_left(s[i], 3);
                                       s[i] = ~v1 + (i<<3) + i;
```

So `out[i] = ror8(~(in[i] - 9*i), 3)`. Running both layers over the literals turns the program legible:

```
`\wiXh4s:%Vs:DKsIa<w_U^Wvk"7)fCzW,...   -> "I know you're watching me.\nAre you one of them?"
?$cE+p'.Y`\S1                            -> "User-Agent"
DMbA6R@/;N^%Q                            -> "schizo 1.0"
6]yW*zKOY`\SLX84\H                       -> "X-Fragment-Key"
3L]eD<;sZY\]GR#k\WQ`ukbiKS               -> "you are not my friend"
^d_oDYHw:D5@M0&"2@=D^ty9JoJlRU^p#K       -> "\nno :) well the truth is\\\"
EcS,dm);vLD=hUNP1vf^rpWBCw               -> "http://127.0.0.1:5566"   (base91 only, no ___4)
```

That last one is the only literal with a single layer, and it explains the `srv.py` in the drop.

##### 5. The flag is never in the binary — it is fetched

`sub_9653` builds the request out of those strings:

```c
sub_1361c(v4, "EcS,dm);vLD=hUNP1vf^rpWBCw", v3);  // http://127.0.0.1:5566
...
(*dat_1046e0)(v10, v9);   // "User-Agent"
(*dat_1046e0)(v13, v12);  // "schizo 1.0"
(*dat_1046e0)(v4,  v16);  // "X-Fragment-Key"
sub_3d7b2(v14, v4, a1);                           // X-Fragment-Key: <arg>
sub_28078(v3, v6, "/", v19, v5);                  // GET /
if (sub_dd4e(v3) != 1)  sub_1361c(a0, "", ...);   // failure -> empty
else                    sub_1aa76(a0, sub_dd70(v3) + 0xb8);   // else response body
```

Five GETs, each carrying a different `X-Fragment-Key`, and the **response body becomes the fragment**. The shipped `srv.py` answers `SILLY!!` to everything, so the stock setup always fails. Whatever the server is supposed to return *is* the flag — which means the flag has to be recoverable from the comparison data.

##### 6. Indexed tables, and `sub_9cc9`

The two `const char*` tables read straight out of `.rodata`:

```bash
$ dd if=schizo bs=1 skip=$((0xc02a0)) count=96 2>/dev/null | xxd
00000000: 3171 6100 3236 4641 3234 0032 5652 2a00  1qa.26FA24.2VR*.
00000010: 3276 3234 336b 6f70 6100 333b 462a 5e26  2v243kopa.3;F*^&
00000020: 0031 716e 3879 7b44 3357 505a 627a 3e00  .1qn8y{D3WPZbz>.
00000030: 3236 5f6f 5066 4723 4f53 7a4f 2461 4100  26_oPfG#OSzO$aA.
00000040: 3256 604b 7458 593c 4c6d 4c6a 3f39 2100  2V`KtXY<LmLj?9!.
00000050: 3276 6234 7571 6578 5e41 6f7b 0033 3b6d  2vb4uqex^Ao{.3;m
```

The entries pair up on a shared two-character prefix — `1q`, `26`, `2V`, `2v`, `3;` — and `sub_9cc9` is what separates prefix from payload. It builds a growing prefix one character at a time, base91-decodes the whole prefix each iteration, and stops as soon as the result is all digits:

```c
sub_2f282(v3, (int)v13);      // v3.push_back(c)  -- v3 accumulates
sub_1aa76(v4, v3);
sub_941d(v5, v4);             // base91-decode the prefix so far
sub_2ecc6(v2, v5);            // v2 = that   (assign, not append)
if (sub_9585(v2)) {           // non-empty && all digits?
  sub_95e1(v5, v6, v4);       //   strip the prefix off the original
  v7 = sub_b9f1(v2, 0, 10);   //   stol -> index
  return {to_string(v7), v5};
}
```

Two characters is always enough, and they decode to exactly `0`–`4` in both tables:

```
'1q' -> b'0'    '26' -> b'1'    '2V' -> b'2'    '2v' -> b'3'    '3;' -> b'4'
```

which splits them into a key table and an expected-value table:

| idx | `X-Fragment-Key` (`0x104610`) | expected (`0x104630`) |
|-----|-------------------------------|------------------------|
| 0   | `a`         | `n8y{D3WPZbz>`  |
| 1   | `FA24`      | `_oPfG#OSzO$aA` |
| 2   | `R*`        | `` `KtXY<LmLj?9! `` |
| 3   | `243kopa`   | `b4uqex^Ao{`    |
| 4   | `F*^&`      | `m;@[q4ob)!]IQ` |

##### 7. `___1` stores its own key in its output

`sub_a286` is the verdict. For each stored response it computes `sub_a1b0` and compares against the table:

```c
sub_a1b0(v10, sub_33c78(0x104650, v3));   // transform the fetched fragment
...
if ((v19 != v20) || (!sub_349d5(v12, v10)))  v1 = 0; else v1 = 1;
```

and `sub_a1b0` is just two calls:

```c
(*dat_1046d0)(v1, a1);        // ___1
sub_3da24(v2, v1);
sub_91af(a0, v2);             // base91-encode
```

So `expected[i] == base91_encode(___1(fragment[i]))`. The fragments are *raw*; only the comparison is transformed. Inverting `___1` gives the flag directly — and `___1` turns out to be a textbook SPN whose key schedule is derived from the plaintext:

```c
for (each byte) v18 += *v16[0];                              // byte sum
v19 = v18 * -0x7a143595 ^ v7 * -0x61c8864f ^ 0xa3c59ac3;     // 0x85EBCA6B / 0x9E3779B1
if (!v19) v19 = 0xcafebabe;
v5 = ((unsigned char)v19 & 7) + 6;                           // 6..13 rounds
build_sboxes(v19 ^ 0xa5a5a5a5, v11, v10);                    // sbox + inverse
build_permutation_sequence(v12, v19 ^ 0x3c3c3c3c, v5);
v13 = v19 ^ 0xc3c3c3c3;                                      // round-key PRNG seed
```

with a round of

```c
state[i] ^= K1[r][i];
state[i]  = sbox[state[i]];
apply_permutation(perm[r], state, tmp); swap(state, tmp);    // out[i] = in[perm[i]]
state[i]  = rotate_left(state[i], (r + i) & 7);
state[i]  = state[i] + K2[r][i];
```

Everything hangs off `v19`, and `v19` depends on the plaintext's byte sum — which should make inversion a search over the sum. It isn't, because of the last four lines of the function:

```c
std::__cxx11::basic_string::reserve(a0, v8 + 5);
pack_u32_be(a0, v19);                            // <- the seed, in the clear
std::__cxx11::basic_string::push_back(a0, v5);   // <- the round count, in the clear
for (v27 = 0; v27 < v8; v27++) push_back(a0, state[v27]);
```

`___1` prepends its own seed and round count to its ciphertext. The output is `be32(seed) || rounds || ct`, so every parameter needed to run the cipher backwards is sitting in the first five bytes of each table entry. Checking that against the entries confirms it before writing any inverse:

```
idx  seed      rounds  (seed & 7) + 6   ct
 0   dbb7e899  7       7  OK            361a427f
 1   b2c43e9b  9       9  OK            08cfe88546
 2   b47f6e28  6       6  OK            f957c92b08
 3   b9778b31  7       7  OK            5cfe0a
 4   d8f2cff9  7       7  OK            bfb16c55f3
```

The primitives are small enough to reimplement verbatim — `xorshift32` is `s ^= s<<13; s ^= s>>17; s ^= s<<5`, `prng_byte` returns bits 8–15, both shuffles are Fisher–Yates over that stream, and `apply_permutation` is `out[i] = in[perm[i]]` so the inverse is `out[perm[i]] = in[i]`. Running each round backwards ([solve.py](solve.py)):

```
$ python3 solve.py
[*] AES-256 key : 098a5c8aebbe8a087e10f4a0a60b9238f41b5566be57068101f5cfd903d9c6f5
[*] IV          : 000102030405060708090a0b0c0d0e0f
[+] lib_dec.so  : 99576 bytes, magic b'\x7fELF'

idx  X-Fragment-Key  seed      rnds  fragment
  0  'a'            dbb7e899  7     b'CMO{'
  1  'FA24'         b2c43e9b  9     b'Th3y_'
  2  'R*'           b47f6e28  6     b'L1K3_'
  3  '243kopa'      b9778b31  7     b'T0_'
  4  'F*^&'         d8f2cff9  7     b'h1d3}'

FLAG: CMO{Th3y_L1K3_T0_h1d3}
```

Two assertions guard each fragment: the recovered plaintext's byte sum must regenerate the stored seed, and re-encrypting must reproduce the table entry byte for byte. Both hold for all five, so this is the plaintext, not merely *a* plaintext.

##### 8. Make the binary say it

Static recovery is not proof. Serving the fragments back over the real socket is ([solve_srv.py](solve_srv.py)):

```python
FRAG = {'a':'CMO{', 'FA24':'Th3y_', 'R*':'L1K3_', '243kopa':'T0_', 'F*^&':'h1d3}'}

def do_GET(self):
    body = FRAG.get(self.headers.get('X-Fragment-Key', ''), '').encode()
    self.send_response(200)
    self.send_header('Content-Length', str(len(body)))
    self.end_headers()
    self.wfile.write(body)
```

Run against the pristine binary, no patches, no debugger:

```bash
$ md5sum schizo
ae49aea1c891ff1dc8acdc232956c861  schizo

$ python3 solve_srv.py &
$ ./schizo
I know you're watching me.
Are you one of them?
CMO{Th3y_L1K3_T0_h1d3}

no :) well the truth is\\\
aHR0cHM6Ly9pbmRlZWQuY29t
```

with the server logging exactly the five expected keys:

```
[srv] UA='schizo 1.0' key='a'       -> b'CMO{'
[srv] UA='schizo 1.0' key='FA24'    -> b'Th3y_'
[srv] UA='schizo 1.0' key='R*'      -> b'L1K3_'
[srv] UA='schizo 1.0' key='243kopa' -> b'T0_'
[srv] UA='schizo 1.0' key='F*^&'    -> b'h1d3}'
```

The parting `aHR0cHM6Ly9pbmRlZWQuY29t` is base64 for `https://indeed.com`, which is the "unemployed crackme" landing where it belongs.

**Flag:** `CMO{Th3y_L1K3_T0_h1d3}`

### Takeaways

A binary that derives its own decryption key by re-reading `/proc/self/exe` has quietly built a tamper check into the unpack step. Here the key is `SHA256(hex(.sforce2))` over a *code* section the program also executes, so patching an anti-debug branch or a comparison inside that section silently corrupts the AES key and the payload never decrypts. The tell is a section with `AX` flags that nothing references as code you can find — read the key derivation before reaching for a patch, or you will be debugging the wrong failure.

Radix errors in hand-rolled codecs are quiet. This one packs two digits into 13 bits, which *looks* like ascii85 in the decompiler and even round-trips short strings into near-ASCII, but the multiplier in the listing is `0x5b`. Reading it as base-85 yields output three off in the first byte — close enough to blame a shift or an off-by-one rather than the constant sitting right there. When a codec is reimplemented from decompiled arithmetic, take the constants literally and validate against a known-plaintext string (`http://127.0.0.1:5566` here) before trusting anything else it decodes.

A cipher whose key schedule depends on the plaintext is not necessarily hard to invert — check whether it has to *transmit* the derived key. `___1` seeds everything from the byte sum and length of its input, which would ordinarily force a search over the sum (a few thousand candidates per fragment, still cheap). But it has to be able to decrypt too, so it prepends the seed and round count to its own output in the clear. One `pack_u32_be` at the end of the function turned a search into a direct inversion.

When the check compares a *transform* of the secret rather than the secret itself, work out which side is printed. `sub_a286` compares `base91(___1(fragment))` against a table but prints the raw fragment, so the table is not the answer and reading it as such gives 61 bytes of noise. Tracing which value reaches `cout` — rather than which value reaches the comparison — is what identifies the thing worth inverting.
