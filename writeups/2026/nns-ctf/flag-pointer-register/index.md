# Flag Pointer Register

- Category: rev
- Difficulty: Beginner
- Author: hoover

"The provided x86-64 .exe decodes the flag successfully, yet it still prints the wrong message. Somewhere between the decoder and WriteFile, a perfectly good pointer ends up in the wrong place."

A one-instruction bug, used as an excuse to learn where the Windows x64 calling convention puts each argument.

### Solution:

##### 1. The decoder works fine

`0x140001000` XORs `0x39` bytes at `0x140003000` against an 8-byte repeating key at `0x140002000`, then returns the decoded buffer in `rax`:

```asm
140001010:  mov    r8d,eax
140001013:  and    r8d,0x7               ; key index = i & 7
140001017:  movzx  r8d,BYTE PTR [r8+rcx*1]
14000101c:  xor    BYTE PTR [rax+rdx*1],r8b
140001023:  cmp    rax,0x39
140001029:  lea    rax,[rip+0x1fd0]      ; return <flag>
140001030:  ret
```

Nothing is wrong here — by the time this returns, the plaintext is sitting in `.data`.

##### 2. `rdx` gets the wrong buffer

Windows x64 passes the first four integer arguments in `rcx`, `rdx`, `r8`, `r9`, so for `WriteFile(hFile, lpBuffer, nBytes, lpWritten, NULL)` the buffer belongs in **`rdx`**. Immediately after the decoder returns:

```asm
1400010b8:  call   0x140001000                  ; rax = decoded flag @ 0x140003000
1400010bd:  mov    rcx,QWORD PTR [rip+0x1f7c]   ; hFile = stdout
1400010c4:  mov    QWORD PTR [rsp+0x20],0x0     ; 5th arg into shadow space
1400010cd:  lea    rdx,[rip+0xf6c]              ; 0x140002040  <-- wrong buffer
1400010d4:  mov    r8d,0x39                     ; ...but the decoder's length
1400010da:  mov    r9,rdi
1400010dd:  call   rbx                          ; WriteFile
```

`rax` is simply discarded and `rdx` is loaded with a static string instead. The length is the tell: `r8d = 0x39` is the decoded buffer's size, not the size of the message that actually gets printed.

```
$ echo | wine flag-pointer-register.exe
Press ENTER to receive the flag.
Access denied: RDX points to the wrong output buffer.
```

##### 3. Put the pointer where WriteFile expects it

Replace the 7-byte `lea rdx,[rip+0xf6c]` with `mov rdx,rax` plus padding. `.text` is VA `0x1000` at raw `0x400`, so the file offset is `0x4cd`:

```
48 8d 15 6c 0f 00 00   ->   48 89 c2 90 90 90 90
```

```
$ echo | wine flag-pointer-register-patched.exe
Press ENTER to receive the flag.
NNS{r4x_h4d_7h3_fl4g_bu7_rdx_p01n73d_70_7h3_wr0ng_buff3r}
```

Live in a debugger the fix is the same instruction by hand: break at `0x1400010dd`, set `RDX = RAX`, continue.

##### 4. Static route

The key and ciphertext are both static, so the patch is only needed to make the program cooperate — not to learn the flag:

```python
key = data[0x600:0x600 + 8]                     # .rdata VA 0x2000 -> raw 0x600
enc = data[0x800:0x800 + 0x39]                  # .data  VA 0x3000 -> raw 0x800
print(bytes(enc[i] ^ key[i & 7] for i in range(0x39)).decode())
```

**Flag:** `NNS{r4x_h4d_7h3_fl4g_bu7_rdx_p01n73d_70_7h3_wr0ng_buff3r}`

### Takeaways

- A length/buffer mismatch is a reliable tell for a swapped pointer. `r8d = 0x39` sitting next to a `lea` of a buffer that clearly isn't `0x39` bytes long says the pointer is wrong, not the length — and that reasoning works without ever running the binary.
- Windows x64 is `rcx, rdx, r8, r9` then stack, and the caller reserves 32 bytes of shadow space, which is why the fifth argument here is written to `[rsp+0x20]` rather than pushed. Reading Win32 call sites is mostly just holding that ordering in mind.
