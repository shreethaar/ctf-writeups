# Open Secret

- Category: rev
- Difficulty: Beginner
- Author: hoover

"The provided x86-64 ELF wants a license file before it will do anything, but it will not tell you which one."

The companion to *No Strings Attached*: same hidden-string idea, but the binary is statically linked and talks to the kernel directly, so the tracer that solved the last one has nothing to attach to.

### Solution:

##### 1. `ltrace` has nothing to hook

```
$ file open-secret
ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

Statically linked, and it contains exactly two functions — `run`, and a hand-rolled syscall thunk:

```asm
0000000000401000 <sys>:
  401014:  mov    rax,QWORD PTR [rbp-0x18]   ; syscall number
  401018:  mov    rdi,QWORD PTR [rbp-0x20]
  401024:  syscall
```

No PLT, no libc, so there is no library-call boundary to instrument. Everything observable happens at the kernel boundary instead — which is what `strace` watches.

##### 2. `strace` the open

```
$ strace -e trace=openat ./open-secret
openat(AT_FDCWD, "/home/user/.config/nns/key", O_RDONLY) = -1 ENOENT (No such file or directory)
no license
+++ exited with 1 +++
```

`run` builds that path itself: it walks `envp` looking for the 5-byte literal `HOME=` at `0x40200c`, copies the matched variable's value into `full` at `0x403060`, then appends 17 decoded bytes and null-terminates before invoking syscall `0x101` (`openat`).

##### 3. Create the file

```
$ mkdir -p ~/.config/nns && touch ~/.config/nns/key
$ ./open-secret
NNS{7h3_p47h_w4s_h1dd3n_bu7_s7r4c3_s4w_7h3_0p3n}
```

An empty file is enough. The syscall immediately after a successful `openat` is `close(fd)` — `mov edi,0x3` at `0x401222` — so the contents are never read. The gate is purely "does this path open".

##### 4. Both secrets ride one keystream

Worth recording for the static route, because it is the one part that isn't obvious: the path and the flag are encrypted with the *same* LCG (`state = state*0x19660d + 0x3c6ef35f`, seed `2`) and the state is **not** reset between them. The 17 path bytes at `0x403000` consume the first 17 keystream bytes, and the 49 flag bytes at `0x403020` continue from byte 18:

```python
s = 2
def k():
    global s
    s = (s * 0x19660d + 0x3c6ef35f) & 0xffffffff
    return (s >> 16) & 0xff

path = bytes(b ^ k() for b in data[path_off:path_off + 17])     # '/.config/nns/key\x00'
flag = bytes(b ^ k() for b in data[flag_off:flag_off + 0x31])
```

Decoding the flag blob with a freshly seeded generator produces garbage — it only comes out if the path is decoded first, in order.

**Flag:** `NNS{7h3_p47h_w4s_h1dd3n_bu7_s7r4c3_s4w_7h3_0p3n}`

### Takeaways

- Check `file` before picking a tracer. "Statically linked" means `ltrace` is blind by construction, and the reflex to try it anyway wastes a run; `strace` still sees everything because syscalls can't be inlined away.
- A file-existence gate that never reads the file is common in these license-check challenges — try `touch` before reverse-engineering an expected format.
- When two blobs share one keystream, the offsets are a dependency, not just a location: decoding blob B requires first consuming exactly as many keystream bytes as blob A used.
