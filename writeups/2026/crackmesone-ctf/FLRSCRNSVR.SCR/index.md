# FLRSCRNSVR.SCR

The binary is a Windows screensaver that displays bouncing frog.

### 1. Analyze entry point

At function `sub_140002BF0` lies the WinMain function prototype that contain the message handler.

```c
sub_140001AE0((wchar_t *)L"Crackmes.one");
// ...
qword_1400089A8 = CreateFontW(..., L"Impact");
// ...
SetTimer(Window, 1u, 0x32u, 0);  // 50ms timer
```

- `sub_140001AE0` is called with `L"Crackmes.one"` as the argument to display the text
- A timer fires every 50 ms for the ainmation loop
- `dword_1400089A4 = rand() % 51 + 10` which is random number of bouncing frog objects (10–60)
- The frog positions are stored as [x, y, dx, dy] quads in `unk_140008A80``
- `ho` = loaded bitmap (the bouncing logo), `hdc` = offscreen DC for double-buffering

At the function `sub_140001AE0`, it contains a global variable of `byte_140008898`. This byte is referred in the flag decryption logic.

### 2. Analyze Window Procedure

At function `sub_140003500`, it contain WndProc that handles all windows messages.

```c
LRESULT __fastcall sub_140003500(HWND a1, UINT a2, WPARAM a3, LPARAM a4)
{
  // WM_TIMER (0x113): bouncing animation + collision detection
  // WM_PAINT (0x0F):  flag decryption and display
  // WM_COMMAND (0x111): menu/dialog handlers
  // WM_DESTROY (0x2): cleanup + PostQuitMessage
}
```

At this function, it contains anti-debug and some junk code that serve no purpose

- `IsDebuggerPresent()` check with a dummy counter loop
- Repeated pointless calls: `GetDesktopWindow()` + `IsWindow()` with discarded results
- `RegOpenKeyExW(... "Control Panel\\Desktop" ...) + RegCloseKey()` — opened and immediately closed
- `FindFirstFileW(... "*.dll" ...) + FindClose()` — opened and immediately discarded
- `QueryPerformanceCounter()` into locals never used
- `SetLastError(GetTickCount() % 100 + 5)` is pure noise

**WM_TIMER** Handler logic:

```c
case 0x113:  // WM_TIMER
    ++dword_140008970;  // tick counter

    // Move all frog, bounce off edges
    for each sprite [x,y,dx,dy]:
        x += dx;  y += dy
        if x out of bounds: dx = -dx
        if y out of bounds: dy = -dy

    // After 600 ticks AND flag not yet set:
    if (dword_140008970 > 600 && !byte_140008899):
        // Check ALL frog pairs for collision via IntersectRect()
        if collision: ++dword_140008984; swap velocities
        if dword_140008984 >= 3000:
            byte_140008899 = 1  // UNLOCK flag display path
```

**WM_PAINT** Handler, the flag logic:

```c
case 0x0F:  // WM_PAINT
    if (byte_140008899) {          // only after 3000 collisions
        // RC4-decrypt SrcBuf (18 bytes) using FindFileData as S-box state
        // ...
        if (SrcBuf[0] == byte_140008898 + 69 &&
            SrcBuf[1] == byte_140008898 + 75 &&
            SrcBuf[2] == 83 - byte_140008898) {
            // SUCCESS: display SrcBuf[3..17] as wide string
            v44 = &DstBuf[3];
        } else {
            v44 = L"Crackmes.one";  // wrong key
        }
    } else {
        v44 = L"Keep Calm and FLARE On";  // not yet unlocked
    }
    DrawTextW(hdc, v44, -1, &Rect, 0x25u);
```

**Encrypted Flag Found:**

```c
xmmword_140008280 = 0B3018B4DF559D6DE60A341962628F9FBh
word_140008290    = 0x346D
```

In memory (little-endian), `SrcBuf[0..17]`:

```
FB F9 28 26 96 41 A3 60 DE D6 59 F5 4D 8B 01 B3 6D 34
```

The decryption uses `FindFileData` as the RC4 S-Box, initialized by `sub_1400010D0`. The magic check requires `byte_140008898` is written. It is set only inside `sub_140001AE0`, the function called from WinMain with `L"Crackmes.one"`.

### 3. Analyze function sub_140001AE0

Traced where `byte_140008898` is written. It is set only inside `sub_140001AE0`, the function called from WinMain with `L"Crackmes.one"`.

```c
LSTATUS sub_140001AE0(wchar_t *Source)
{
    // Check registry: HKCU\Software\FLRSCRNSVR
    if (RegOpenKeyExW(..., L"Software\\FLRSCRNSVR", ...) FAILS) {
        wcscpy_s(Source, 0x100u, L"Crackmes.one");  // no key = default
        return;
    }

    // Key exists: read "Text" value into Source
    RegQueryValueExW(hKey, L"Text", ..., Source, ...);

    // Must be exactly 25 wide characters
    if (wcsnlen(Source, 0x100u) == 25) {
        sub_140001300(Destination);   // transform Source in-place
        sub_140001890(v35);           // generate expected value

        // Compare transformed input vs expected
        if (Destination == v35) {
            byte_140008898 = 1;       // PASSWORD CORRECT
        }
    }
}
```

- User create registry key `HKCU\Software\FLRSCRNSVR` with a string value `Text`
- The value must be exactly 25 wide characters
- It is passed through a transform pipeline (`sub_140001300`) and compared to a stored expected value (`sub_140001890`)
- If they match: `byte_140008898 = 1`

With `byte_140008898 = 1`, the magic check becomes:

```c
dec[0] == 1 + 69 == 70  == 'F'
dec[1] == 1 + 75 == 76  == 'L'
dec[2] == 83 - 1 == 82  == 'R'
```

The magic header is "FLR" as in FLARE. The RC4 key is the 25 characters password itself.

### 4. RC4 KSA

Decompiled the S-box initializer to confirm the cipher type and key derivation.

```c
BOOL sub_1400010D0(unsigned __int8 *a1, __int64 a2, int a3)
{
    // Standard RC4 Key Scheduling Algorithm (KSA)
    // a1 = S-box (FindFileData struct, 256+ bytes)
    // a2 = key pointer (Dst = ASCII "Crackmes.one" or the actual password)
    // a3 = key length

    // Step 1: Initialize S[0..255] = [0..255]
    for (i = 0; i < 256; i++) *v7++ = i;

    // Step 2: KSA
    do {
        v9 = (S[i] + key[i % a3] + v9) % 256;
        swap(S[i], S[v9]);
    } while (++v6 < 256);

    a1[256] = 0;  // i = 0
    a1[257] = 0;  // j = 0
}
```

- Pure standard RC4 KSA. All the `RegOpenKeyExW`, `FindFirstFileW`, `GetStockObject` calls inside are junk.
- `sub_1400010D0()` always return `0`  
- Key length = `wcstombs_s output (26 bytes for 25 chars + null) - 0 - 1 = 25`
The RC4 key is the 25-character password as 25 ASCII bytes

### 5. Analyze transform pipeline function

At function `sub_140001300`, reversed the password transformation to understand how to invert it.

Stage 1: Substitution cipher

```c
wcscpy_s(Destination, L"abcdefghijklmnopqrstuvwxyz"
                       L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       L"0123456789}_{=-");            // source alphabet
wcscpy_s(v43, L"-={_}9876543210ZYXWVUTSRQPONMLKJIHGF"
               L"EDCBAzyxwvutsrqponmlkjihgfedcba");   // dest alphabet

for each char in input:
    idx = find(char, source_alphabet)
    if found: input[i] = dest_alphabet[idx]
```

Stage 2: XOR with "FLAREALF" Key

```c
// v32 as WORDs: 0x0046, 0x004C, 0x0041, 0x0052, 0x0045,
//               0x0052, 0x0041, 0x004C, 0x0046  = "FLARERALF"
for (j = 0; j < 25; j++):
    input[j] ^= (FLARERALF[j % 9] + j) & 0xFF
```

The XOR key FLARERALF is a 9-character palindrome of "FLARE" embedded as integer constants 4980806, 5374017, 5374021, 4980801, 70.

Stage 3: String reversal

```
for i in range(25 // 2):
    swap(input[i], input[24 - i])
```

### 6. Expected value at `sub_140001890` + `aQj`

Analyzed `sub_140001890` to find the comparison target, then located the hardcoded fallback string `aQj` in IDA's `.rdata` section.

`aQj` Raw Bytes (from `.rdata:00000001400064D0`)

```
UTF-16LE: '<', 'Q', 'j', 0x09, 0x02, 0x07, '%', 0x03, '0',
           0x08, 0x04, ')', 'h', '$', 0x01, '$', 0x18,
           'k', 'w', 0x0F, 'p', '6', 0x02, 0x0E, 0x0B
```

This is the expected output of sub_140001300(correct_password). Inverting the transform on aQj gives us the password directly.

Here is the solve script:

```
#!/usr/bin/env python3
"""
Crackme Solve Script
Recovers password and decrypts flag from hardcoded constants.
"""

# ── Constants from binary ────────────────────────────────────────────────────

# Encrypted flag: xmmword_140008280 (16 bytes LE) + word_140008290 (2 bytes LE)
SRCBUF = bytes([
    0xFB, 0xF9, 0x28, 0x26, 0x96, 0x41, 0xA3, 0x60,
    0xDE, 0xD6, 0x59, 0xF5, 0x4D, 0x8B, 0x01, 0xB3,
    0x6D, 0x34
])

# aQj from .rdata:00000001400064D0 (25 UTF-16LE wchars, null-terminated)
AQJ = [
    0x3C, 0x51, 0x6A, 0x09, 0x02, 0x07, 0x25, 0x03,
    0x30, 0x08, 0x04, 0x29, 0x68, 0x24, 0x01, 0x24,
    0x18, 0x6B, 0x77, 0x0F, 0x70, 0x36, 0x02, 0x0E, 0x0B
]

# Substitution alphabets from sub_140001300
SRC_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
DST_ALPHA = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

# XOR key: v32 integers decoded as WORDs = "FLARERALF" (9 chars)
XOR_KEY = [0x46, 0x4C, 0x41, 0x52, 0x45, 0x52, 0x41, 0x4C, 0x46]

# byte_140008898 = 1 (set when password is correct)
MAGIC_BASE = 1


# ── Step 1: Invert sub_140001300 on aQj to recover password ─────────────────

def invert_transform(arr):
    """
    Inverse of sub_140001300:
      forward:  substitute -> XOR with FLARERALF+pos -> reverse
      inverse:  un-reverse -> un-XOR -> un-substitute
    """
    arr = list(arr)
    n = len(arr)

    # Un-reverse (Stage 3 inverse)
    for i in range(n // 2):
        arr[i], arr[n - 1 - i] = arr[n - 1 - i], arr[i]

    # Un-XOR (Stage 2 inverse — XOR is self-inverse)
    for j in range(n):
        xor_val = (XOR_KEY[j % 9] + j) & 0xFF
        arr[j] = arr[j] ^ xor_val

    # Un-substitute (Stage 1 inverse)
    for i in range(n):
        ch = chr(arr[i])
        idx = DST_ALPHA.find(ch)
        if idx != -1:
            arr[i] = ord(SRC_ALPHA[idx])

    return arr


password_ints = invert_transform(AQJ)
password_str  = ''.join(chr(c) for c in password_ints)
password_bytes = bytes(c & 0xFF for c in password_ints)

print(f"[+] Recovered password ({len(password_str)} chars): {password_str!r}")


# ── Step 2: RC4 decrypt SrcBuf using password as key ────────────────────────

def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


decrypted = rc4_decrypt(password_bytes, SRCBUF)

print(f"[+] Decrypted bytes: {decrypted.hex()}")


# ── Step 3: Verify magic header and extract flag ─────────────────────────────

d0, d1, d2 = decrypted[0], decrypted[1], decrypted[2]
magic_ok = (
    d0 == MAGIC_BASE + 69 and   # 'F'
    d1 == MAGIC_BASE + 75 and   # 'L'
    d2 == 83 - MAGIC_BASE        # 'R'
)

print(f"[+] Magic header: '{chr(d0)}{chr(d1)}{chr(d2)}' — {'PASS' if magic_ok else 'FAIL'}")

flag = decrypted[3:].decode('ascii', errors='replace')
print(f"\n{'='*50}")
print(f"    FLAG: {flag}")
print(f"{'='*50}")
```

**FLAG:** `CMO{frogt4s7ic_r3vers1ng}`
