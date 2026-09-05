# Patch Tuesday

- Category: rev
- Author: hoover

"The provided x86-64 .exe promises a free flag, but it does not behave the way we want."

The check standing in the way isn't merely hard to satisfy, it's unsatisfiable — the slot being compared can never hold the value it's compared against, whatever you type. Patching isn't a shortcut here, it's the only route.

### Solution:

##### 1. The compare, and why no input passes it

```asm
140001079:  mov    ecx,DWORD PTR [rsp+0x34]
14000107d:  call   0x140001160
140001082:  test   eax,eax
140001084:  je     0x140001088        ; -> jmp 0x140001127, "Sorry, no free flag for you."
140001086:  jmp    0x14000108d        ;    the flag path

140001160:  xor    eax,eax
140001162:  cmp    ecx,0x1337
140001168:  sete   al
14000116b:  ret
```

So it wants `[rsp+0x34] == 0x1337` (4919). Typing `4919` does nothing, because `[rsp+0x34]` never holds your input:

```asm
14000105e:  lea    rdx,[rip+0x1ffb]         ; lpBuffer -> 0x140003060
140001065:  lea    r9,[rsp+0x34]            ; lpNumberOfBytesRead
14000106a:  mov    rcx,rsi                  ; hStdInput
14000106d:  mov    r8d,0x10                 ; nNumberOfBytesToRead = 16
140001073:  call   QWORD PTR [rip+0x1067]   ; ReadFile
```

`r9` is `ReadFile`'s fourth argument, `lpNumberOfBytesRead`, and it points at the very dword that gets compared. The typed bytes land at `0x140003060` and are never read again. What's checked against 4919 is the *byte count* — capped at 16 by `r8d`, so it cannot get there.

##### 2. Patch the branch

`je 0x140001088` at `0x140001084` is the two-byte `74 02`, and the instruction directly after it is the unconditional jump into the flag path. NOP-ing the `je` makes every run fall through to success. `.text` is VA `0x1000` at raw `0x400`, so the file offset is `0x400 + (0x1084 - 0x1000)` = `0x484`:

```
74 02   ->   90 90
```

```
$ echo | wine free-flag-patched.exe
Press ENTER to get a free NNS{ flag: Correct! Here is your free flag: NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}
```

In a debugger the equivalent is flipping ZF at `0x140001084`, or just setting `RIP` to `0x14000108d`.

##### 3. Or decode it statically

The flag path is a single-byte XOR over `.data`, which needs no patching at all:

```asm
1400010a0:  xor    BYTE PTR [rax+rcx*1],0x5a
1400010a4:  inc    rax
1400010a7:  cmp    rax,0x4c
```

```python
blob = data[0x800:0x800 + 0x4c]        # .data VA 0x3000 -> raw 0x800
print(bytes(b ^ 0x5a for b in blob).decode())
```

**Flag:** `NNS{1_h0p3_y0u_p47ch3d_7h3_0pc0d3_dur1ng_run71m3_jnz_15_much_b3773r_7h4n_jz}`

### Takeaways

- When a comparison looks impossible to satisfy, check whether the compared slot is an *output parameter* of a nearby Win32 call. `lpNumberOfBytesRead` aliasing the checked variable is the entire gimmick, and it reads as an ordinary `lea` unless you know the argument order.
- Prefer NOP-ing a conditional jump over inverting it. `je` → `jne` also redirects the path that was previously succeeding, which quietly breaks the branch you wanted to keep; NOPs only remove the branch you meant to remove.
