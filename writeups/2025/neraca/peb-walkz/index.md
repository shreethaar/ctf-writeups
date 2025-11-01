### 2. PEB Walkz

- Base address: `0000000140000000`
- Entry point: `00000001400014f0`

![pebwalkz1.png](pebwalkz1.png)


##### 1. Analyze main function 
main function is at address `00000001400013bf`, here is the decompiled C code:
  ```c
  // write access to const memory has been detected, the output may be wrong!
__int64 __fastcall sub_140001190(__int64 a1, __int64 a2)
{
  _STARTUPINFOA *p_StartupInfo; // r8
  __int64 v3; // rcx
  PVOID StackBase; // rsi
  signed __int64 v5; // rax
  int v6; // ebp
  char **v7; // rax
  char v8; // cl
  char *v9; // rax
  char v10; // dl
  char v11; // dl
  int wShowWindow; // eax
  int v13; // ebx
  size_t v14; // r12
  _QWORD *v15; // rax
  __int64 v16; // r13
  __int64 v17; // rdi
  __int64 v18; // rbp
  __int64 v19; // rbx
  size_t v20; // rsi
  void *v21; // rax
  __int64 v22; // rax
  __int64 result; // rax
  _STARTUPINFOA StartupInfo; // [rsp+20h] [rbp-A8h] BYREF

  p_StartupInfo = &StartupInfo;
  memset(&StartupInfo, 0, sizeof(StartupInfo));
  v3 = 0;
  if ( unk_14000D090 )
    GetStartupInfoA(&StartupInfo);
  StackBase = NtCurrentTeb()->NtTib.StackBase;
  while ( 1 )
  {
    v5 = _InterlockedCompareExchange64(qword_14000DB98, (signed __int64)StackBase, 0);
    if ( !v5 )
    {
      v6 = 0;
      if ( unk_14000DB90 == 1 )
        goto LABEL_39;
      goto LABEL_8;
    }
    if ( StackBase == (PVOID)v5 )
      break;
    Sleep(0x3E8u);
  }
  v6 = 1;
  if ( unk_14000DB90 == 1 )
  {
LABEL_39:
    amsg_exit(31, a2, p_StartupInfo);
    if ( unk_14000DB90 == 1 )
      goto LABEL_40;
LABEL_11:
    if ( v6 )
      goto LABEL_12;
    goto LABEL_41;
  }
LABEL_8:
  if ( unk_14000DB90 )
  {
    dword_14000D008 = 1;
  }
  else
  {
    unk_14000DB90 = 1;
    initterm(&qword_14000F018, qword_14000F030);
  }
  if ( unk_14000DB90 != 1 )
    goto LABEL_11;
LABEL_40:
  initterm(&qword_14000F000, &qword_14000F010);
  unk_14000DB90 = 2;
  if ( v6 )
    goto LABEL_12;
LABEL_41:
  _InterlockedExchange64(qword_14000DB98, 0);
LABEL_12:
  if ( TlsCallback_0 )
    TlsCallback_0(0, 2, 0);
  sub_140001AB0(v3, a2, p_StartupInfo);
  qword_14000D0D0 = (__int64)SetUnhandledExceptionFilter(TopLevelExceptionFilter);
  sub_1400077E0(nullsub_1);
  sub_140001810();
  qword_14000DB88 = (__int64)off_14000A740;
  v7 = (char **)sub_1400078C0();
  v8 = 0;
  v9 = *v7;
  if ( !v9 )
    goto LABEL_27;
  while ( 1 )
  {
    v10 = *v9;
    if ( *v9 <= 32 )
      break;
    if ( v10 == 34 )
      v8 ^= 1u;
LABEL_19:
    ++v9;
  }
  if ( !v10 )
    goto LABEL_26;
  if ( (v8 & 1) != 0 )
  {
    v8 = 1;
    goto LABEL_19;
  }
  do
    v11 = *++v9;
  while ( v11 && v11 <= 32 );
LABEL_26:
  qword_14000DB80 = (__int64)v9;
LABEL_27:
  if ( unk_14000D090 )
  {
    wShowWindow = 10;
    if ( (StartupInfo.dwFlags & 1) != 0 )
      wShowWindow = StartupInfo.wShowWindow;
    dword_140009000 = wShowWindow;
  }
  v13 = dword_14000D028;
  v14 = 8LL * (dword_14000D028 + 1);
  v15 = malloc(v14);
  v16 = qword_14000D020;
  v17 = (__int64)v15;
  if ( v13 > 0 )
  {
    v18 = (unsigned int)(v13 - 1);
    v19 = 0;
    do
    {
      v20 = strlen(*(const char **)(v16 + 8 * v19)) + 1;
      v21 = malloc(v20);
      *(_QWORD *)(v17 + 8 * v19) = v21;
      memcpy(v21, *(const void **)(v16 + 8 * v19), v20);
      v22 = v19++;
    }
    while ( v18 != v22 );
    v15 = (_QWORD *)(v17 + v14 - 8);
  }
  *v15 = 0;
  qword_14000D020 = v17;
  sub_140001600();
  _initenv = qword_14000D018;
  result = sub_140007CF0((unsigned int)dword_14000D028, qword_14000D020);
  dword_14000D010 = result;
  if ( !dword_14000D00C )
    exit(result);
  if ( !dword_14000D008 )
  {
    cexit();
    return (unsigned int)dword_14000D010;
  }
  return result;
}
  ```

From the decompiled C code, it performs:
- Dynamic API resolution
- Brute-force key to decrypt shellcode
- Check valid shellcode with `48 81 e4 f0` hex pattern
- VirtualAlloc + CreateThread to execute shellcode

Encrypted shellcode is at `0x140009108`, here is the script to decrypt the shellcode:
```python
#!/usr/bin/env python3
import re
from pathlib import Path

# Paste the raw hexdump/text you posted (or the raw dumped block) between the triple quotes.
# Keep the addresses, ascii column, etc — the script will extract only hex byte pairs.
hexdump_text = r"""
71 49 99 99 99 d8 c8 d8 c9 cb c8 cf d1 a8 4b fc d1 12 cb f9 a7 d1 12 cb
81 a7 d1 12 cb b9 a7 d1 12 eb c9 a7 d1 96 2e d3 d3 d4 a8 50 d1 a8 59 35 a5 f8 e5 9b b5 b9 d8 58
50 94 d8 98 58 7b 74 cb d8 c8 a7 d1 12 cb b9 a7 12 db a5 d1 98 49 a7 12 19 11 99 99 99 d1 1c 59
ed f6 d1 98 49 c9 a7 12 d1 81 a7 dd 12 d9 b9 d0 98 49 7a c5 d1 66 50 a7 d8 12 ad 11 d1 98 4f d4
a8 50 d1 a8 59 35 d8 58 50 94 d8 98 58 a1 79 ec 68 a7 d5 9a d5 bd 91 dc a0 48 ec 4f c1 a7 dd 12
d9 bd d0 98 49 ff a7 d8 12 95 d1 a7 dd 12 d9 85 d0 98 49 a7 d8 12 9d 11 d1 98 49 d8 c1 d8 c1 c7
c0 c3 d8 c1 d8 c0 d8 c3 d1 1a 75 b9 d8 cb 66 79 c1 d8 c0 c3 a7 d1 12 8b 70 d0 66 66 66 c4 d0 5e
58 99 99 99 99 a7 d1 14 0c 67 99 99 99 a7 d5 14 1c 83 98 99 99 d1 a8 50 d8 23 dc 1a cf 9e 66 4c
d1 a8 50 d8 23 69 2c 3b cf 66 4c cb ce ca da e2 ac f1 aa a8 a8 c6 fa a9 fd aa c6 fd aa fb ec a0
a0 a8 f7 a0 e3
"""

# If your hexdump included the "data_140009225" tail as a separate line, append it here (optional)
tail_hex = "99dacacecb99e4"  # update if different or leave as "" if already included above

# Extract all two-hex-digit tokens (this ignores addresses, ascii, and non-hex junk)
hex_pairs = re.findall(r'[0-9a-fA-F]{2}', hexdump_text)
if tail_hex:
    # ensure tail is split into pairs and appended
    tail_pairs = re.findall(r'[0-9a-fA-F]{2}', tail_hex)
    hex_pairs += tail_pairs

if not hex_pairs:
    raise SystemExit("No hex bytes found in the pasted hexdump. Make sure you pasted the correct block.")

blob = bytes.fromhex(''.join(hex_pairs))
print(f"Blob length = {len(blob)} bytes")

# Brute-force single-byte XOR searching for shellcode prefix
target_prefix = b"\xFC\x48\x81\xE4\xF0"

def find_key_and_decrypt(blob, prefix):
    for k in range(256):
        dec = bytes(b ^ k for b in blob)
        if dec.startswith(prefix):
            return k, dec
    return None, None

key, dec = find_key_and_decrypt(blob, target_prefix)
if key is None:
    print("No single-byte XOR key produced the expected prefix.")
    # Helpful diagnostics: show bytes for keys that fix the first byte only
    first = blob[0]
    cand = [k for k in range(256) if (first ^ k) == target_prefix[0]]
    print("Keys that make first byte match:", cand[:50], f"(count {len(cand)})")
else:
    print(f"Found key: 0x{key:02x} ({key})")
    out = Path("decrypted_shellcode.bin")
    out.write_bytes(dec)
    print(f"Wrote decrypted blob to {out} ({len(dec)} bytes)")
    print("First 64 bytes (hex):", dec[:64].hex())
```

**Flag:** `RWSC{5h311_c0d3_d3bu991n9z}`


