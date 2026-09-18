# HollowDex

- Category: rev

"HollowDex Vault is an Android credential checker. Enter the right 32-character hex key and it grants access. The APK is straightforward. The native library loads quietly. The Java method that does the checking is right there in the DEX. Except it isn't."

A 17 KB APK: one activity, one `Verifier` class, one 5.6 KB `arm64-v8a` library. The prompt's last line is literal — `Verifier.verifyFlag` exists in the DEX with a method body, but the bytes of that body are not instructions. The library rewrites them in memory at load time, so the method you decompile is never the method that runs.

### Solution:

##### 1. The method body is not bytecode

jadx handles everything except the one method that matters:

```
$ jadx -d out classes.dex
...
public boolean verifyFlag(java.lang.String r14) {
    /* Can't load method instructions: Load method exception:
       JadxRuntimeException: Failed to decode insn: 0x0006: UNKNOWN(0xC0E9)
       in method: com.hollowdex.Verifier.verifyFlag(java.lang.String):boolean */
```

`0xC0E9` is not an opcode. `MainActivity` decompiles fine and is as thin as the prompt suggests — `verifyFlag` decides everything:

```java
if (this.verifier.verifyFlag(editText.getText().toString().trim())) {
    textView.setText("ACCESS GRANTED");
} else {
    textView.setText("ACCESS DENIED");
}
```

The native side exports exactly one symbol, and it is not a JNI binding:

```
$ nm -D --defined-only lib/arm64-v8a/libhollowdex.so
0000000000001900 T JNI_OnLoad
```

No `Java_com_hollowdex_Verifier_verifyFlag`. So the library is not *implementing* the check natively — it is doing something to the DEX. Its string table says what:

```
/proc/self/maps        com/hollowdex/Verifier      .apk
/proc/self/mem         (Ljava/lang/String;)Z       r--p
%lx-%lx                verifyFlag                  r-xp
```

##### 2. `JNI_OnLoad` locates the loaded DEX and its code item

Decompiled, the flow is short. It resolves the method, keeps the `ArtMethod` field at offset 8, then walks the process map looking for the mapped APK — confirming the hit by checking the mapping actually begins with the `dex\n` magic rather than trusting the path:

```c
v8 = FindClass(env, "com/hollowdex/Verifier");
v8 = GetMethodID(env, v8, "verifyFlag", "(Ljava/lang/String;)Z");
v2 = *(unsigned int *)(v8 + 8);          // dex_code_item_offset_

v9 = fopen("/proc/self/maps","r");
while (v10) {
  if (strstr(v4,".apk") && (strstr(v4,"r--p") || strstr(v4,"r-xp"))
      && sscanf(v4,"%lx-%lx",&v5,v6) == 2
      && v5[0]=='d' && v5[1]=='e' && v5[2]=='x' && v5[3]=='\n') goto found;
  v10 = fgets(v4,0x200,v9);
}
```

With the DEX base in hand, the code item is base + that offset, and the standard `code_item` layout gives the instruction array:

```c
v1  = &v10[v2];                  // code_item
v15 = &v1[0x10];                 // insns[]
v2  = *(int *)&v1[0xc] << 1;     // insns_size (16-bit units) * 2 = byte length
```

##### 3. A 16-byte XOR, written back through `/proc/self/mem`

The copy loop is vectorised to 32 bytes at a time, but the scalar tail is the authoritative statement of the key length:

```c
*(unsigned char *)((long)v9 + v12) = *(unsigned char *)((unsigned long)v4 | v12 & 0xf) ^ v15[v12];
```

`v12 & 0xf` — a 16-byte repeating key, and `v4` was loaded from `.rodata` at `0x700`:

```
$ xxd -s 0x700 -l 16 lib/arm64-v8a/libhollowdex.so
00000700: 590e 7a65 14c3 bea1 e3c1 e781 e3c1 ef01
```

The decrypted buffer is then written over the live mapping — the read-only DEX page is bypassed by writing to the process's own memory through the proc filesystem rather than by `mprotect`:

```c
v7 = open("/proc/self/mem", 2);
if (0 <= v7) { lseek(v7, v15, 0); write(v7, v9, v16); close(v7); }
```

##### 4. Do the patch offline instead

No device or emulator needed — everything the library computes at runtime is derivable from the DEX file. Parse the class data to find `verifyFlag`'s `code_off`, XOR `insns[]` with the key, and repair the header:

```
$ ./patch_dex.py
  virtual verifyFlag     code_off=0x62c
verifyFlag code_item @ 0x62c
insns_size=156 units -> 312 bytes at 0x63c
encrypted: 4b0e426b8ec3d0b1f4c1e981e9c0fc03790e484410c397a173c1f480f3c1cc13...
decrypted: 1200380e9a006e1017000e000a011302200032210400290090001301100023121a...
wrote patched.dex
```

`12 00` = `const/4 v0, 0`, `38 0e 9a00` = `if-eqz v14, +0x9a`, `6e 10 1700 0e00` = `invoke-virtual {v14}` — real bytecode.

One gotcha: a DEX header carries an **Adler-32** checksum at offset 8, not a CRC-32. Getting that wrong produces a file every tool silently refuses to load, with jadx reporting only `No classes to decompile`. The SHA-1 signature at offset 12 covers everything from offset 32 on, and the checksum covers everything from offset 12 on — so they have to be recomputed in that order.

Full script: [patch_dex.py](patch_dex.py)

##### 5. The real check is a 3-round Feistel

With the patched DEX, jadx produces the method the prompt promised:

```java
public boolean verifyFlag(String str) {
    if (str == null || str.length() != 32) return false;
    byte[] bArr = new byte[16];
    for (int i = 0; i < 16; i++) { /* hex-decode into bArr */ }

    long j = 0, j2 = 0;
    for (int i3 = 0; i3 < 8; i3++) j2 = (j2 << 8) | (255 & ((long) bArr[i3]));
    for (int i4 = 0; i4 < 8; i4++) j  = (j  << 8) | (((long) bArr[i4 + 8]) & 255);

    long j3 = j + 2611923443488327891L;
    long j4 = 2611923443488327891L ^ (j2 ^ ((j3 >>> 47) | (j3 << 17)));
    long j5 = j4 + 1376283091369227076L;
    long j6 = (j ^ ((j5 >>> 47) | (j5 << 17))) ^ 1376283091369227076L;
    long j7 = j6 - 6626703657320631856L;
    return (j6 == 6146647970834606741L)
         & (((j4 ^ ((j7 >>> 47) | (j7 << 17))) ^ (-6626703657320631856L))
            == -5423340355720311942L);
}
```

`(v >>> 47) | (v << 17)` is `rotl64(v, 17)`, and the third round's `- 6626703657320631856` is `+ K3` mod 2^64 for the same `K3` it XORs with. So every round is the same shape:

```
round(prev, cur, K) = prev ^ rotl17(cur + K) ^ K

j4 = round(L,  R,  K1)
j6 = round(R,  j4, K2)      <- checked against T4
j8 = round(j4, j6, K3)      <- checked against T5
```

##### 6. Invert it

Each round is a bijection in its first argument, so `(j6, j8)` determines `j4`, then `R`, then `L` — no search, and the key is unique:

```python
j4 = round(T5, T4, K3)
R  = round(T4, j4, K2)
L  = round(j4, R,  K1)
key = L.to_bytes(8, "big") + R.to_bytes(8, "big")
```

```
$ ./solve.py
key (32 hex) : c19e6e4be6148b5581809ae7291c9cfe
verifyFlag   : True
flag         : CTF{7295614c872c071d88fe8b29b5af155fd44f837b5d986f5d74a2524de883241b}
```

The verification is a literal re-transcription of the Java — signed 64-bit wrap, `>>>` as a logical shift — rather than a re-run of the same `round()` helper used to invert it, since checking an inverse with its own forward function proves nothing.

Full script: [solve.py](solve.py)

##### 7. The flag is the hash of the key bytes

The stated format is `CTF{sha256}`, but nothing in the APK computes a digest — `MainActivity` only toggles two strings, and the library only patches bytecode. The hashing is a submission convention, and it is taken over the **raw 16 decoded bytes**, not over their ASCII hex spelling:

```
sha256(bytes.fromhex(key))   7295614c872c071d88fe8b29b5af155fd44f837b5d986f5d74a2524de883241b   accepted
sha256(key.encode())         712ce34b07c19165180e69583257151dd56963a04989272bc55a249ab5e98cb5   rejected
sha256(key.upper().encode()) fa59a231aaa8a76f947e0378fd206bf747824e004faf4ad5c1d58722b6862f9a   rejected
```

**Flag:** `CTF{7295614c872c071d88fe8b29b5af155fd44f837b5d986f5d74a2524de883241b}`

### Takeaways

- A JNI library that exports only `JNI_OnLoad` and nothing named `Java_*` is not implementing anything for Java — it is doing something *to* the runtime. Check its strings for `/proc/self/maps` and `/proc/self/mem` before assuming the logic moved to native code.
- `/proc/self/mem` is a write primitive that ignores page protections, so a read-only DEX mapping is not evidence the bytecode can't change under you. A method body that fails to disassemble is a strong tell for this pattern rather than a broken file.
- Runtime self-modification can almost always be reproduced statically. Everything `JNI_OnLoad` did — locate the code item, XOR with a fixed key, write it back — is computable from the APK alone, which turns an emulator-and-Frida problem into a Python script.
- When rebuilding a DEX, it is Adler-32 at offset 8. A wrong checksum fails silently as "no classes found", which reads exactly like a bad patch offset and costs time in the wrong place.
- `CTF{sha256}` in a prompt does not say *what* is hashed. When the artifact contains no SHA-256 at all, that step is a scoreboard convention and worth trying over the raw bytes before the hex string.
