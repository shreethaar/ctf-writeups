# BrunnerCorp Pre-Employment Aptitude Test

- Category: rev
- Difficulty: Hard
- Author: OddNorseman
- Status: Not solved live — post-mortem, reconciled against the solutions shared in post-CTF Discord discussion

"We only consider applicants with a score of over 9000." A 2.7 MB Rust-compiled Windows PE opens a Win32 aim-trainer: circles spawn, you click them, and after a one-hour session it writes an encrypted `aim-score.bin`, which you upload to an online checker that returns the flag if the score clears 9000. That last sentence is the whole challenge — and the thing that got missed live, spending the whole session reversing a subsystem that turned out to be irrelevant to the flag.

### Solution:

##### 1. What got reversed (correct, but off the critical path)

`main` funnels into `anticheat::integrity::validate_and_execute_package`, a gauntlet of gates: anti-debug, package location, header/manifest verification, key derivation, a second/third anti-debug pass, a challenge/response check, a custom bytecode VM ("VM integrity check failed"), payload decryption, then `game::run()`.

The package is appended to the executable itself (trailer magic `"ACEX001\0"`, version, size, key material), containing an inner `"ACPT001\0"` package that decrypts to `anticheat.exe`. Every crypto primitive here is a well-known non-cryptographic one, identifiable by its constants: SplitMix64 finalizer (`0xbf58476d1ce4e5b9`), FNV-1a-64 (`0x100000001b3`), xorshift64\* (`0x2545F4914F6CDD1D`), and a golden-ratio mix constant (`0x9E3779B97F4A7C15`). Notably, `verify_header` compares against a plain FNV-1a hash sitting right there in the header — corruption detection, not authentication; anyone controlling the package bytes can recompute a matching manifest.

The integrity VM is a 4-register bytecode interpreter (opcodes `LOAD`/`XCHK`/`ACHK`/`ROL`/`KEYMIX`/`CMP`/`JZ`/`MASK`) whose check logic lives entirely in bytecode data, not native instructions. Anti-debug is a single choke-point function (`windows::detect_debugger`) layering `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, three `NtQueryInformationProcess` checks, two PEB field checks, and two more stripped-symbol checks — both call sites in the binary funnel through it.

All of this is verified correct against the shipped binary. None of it is on the path to the flag.

##### 2. Where the analysis went wrong

**The flag was never in the binary at all.** The binary produces an artifact (`aim-score.bin`); a server elsewhere validates that artifact. No amount of reversing the loader, the VM, or the anti-debug stack gets you there — the exploitable surface was always `anticheat::game::*`, glanced at once and set aside because the `anticheat::` tree's sophistication was more attention-grabbing than the actual data flow ("what does this program produce, and who consumes it?").

##### 3. The intended solution — forge the score file

The score file's encryption has nothing to do with the elaborate container crypto — a repeating-key XOR with a position-dependent counter, self-inverse, with the key sitting in plaintext in `.rdata`:

```python
KEY = b"BrunnerAimTrainer-static-key"

def xorcrypt(data: bytes) -> bytes:
    return bytes((b ^ (i * 17) ^ KEY[i % len(KEY)]) & 0xFF
                 for i, b in enumerate(data))
```

Decrypted format:

```
Header (42 bytes):  <14s Q I I I I I>
    signature  b"BRUNNER-AIM-1\x00"
    seed       u64
    width, height, score, clicks, circles   u32 each

Click  (24 bytes):  <Q i i i i>       time, x, y, win_w, win_h
Circle (36 bytes):  <Q i i i i i Q>   start, x, y, radius, win_w, win_h, end
```

You can't just bump the `score` field — the online checker re-derives the entire circle sequence from the seed and validates it. Circles come from a **xorshift64** PRNG (`<<13`, `>>7`, `<<17` — a different shift triple from the container's xorshift64\*):

```python
class PRNG:
    def __init__(self, seed): self.state = seed | 1
    def generate(self):
        self.state ^= (self.state << 0xd) & 0xffffffffffffffff
        self.state ^=  self.state >> 7
        self.state ^= (self.state << 0x11) & 0xffffffffffffffff
        return self.state & 0xffffffff

def generate_coords(prng, radius, width, height):
    x = radius + prng.generate() % max(width - radius * 2, 1)
    y = 70     + prng.generate() % max(height - radius - 70, 1)
    return x, y
```

Radius and per-circle duration both shrink linearly across the one-hour session — the "harder goals as the deadline approaches" flavor text, made literal. Starting at `t = 75` and accumulating durations until the hour expires yields exactly 14,162 circles, the theoretical maximum score. Placing one click at each circle's `(start, x, y)` hits every target.

Re-implementing this and checking it against the winning `aim-score.bin` shared in Discord: all 14,162 circles regenerate bit-for-bit from the seed alone — the forgery is fully deterministic. The practical route (Nissen): run the game with Cheat Engine speedhack to get one valid file quickly, use it to learn the format, then generate a synthetic file with correct timings and maximal clicks.

##### 4. The unintended solution — patch and automate

1. Patch out the anti-debug
2. Run under `wine` + GDB via pwntools
3. Breakpoint at the coordinate-generation code, read `x`/`y`/`r` out of `$edi`/`$ebp`/`$eax`
4. `xdotool mousemove` + `click` at those coordinates

The patch is three bytes — diffing the supplied binaries: file offset `0xff40` (`anticheat::anti_debug::abort_if_debugged`) changes `41 56 56` (`push r14; push rsi`) to `31 c0 c3` (`xor eax, eax; ret`), stubbing the exact choke-point function identified in Part 1 to unconditionally report "no debugger." This approach (MrOdin) ultimately topped out at 8927 — short of 9000 — because in the final minute the circles cycle faster than `xdotool` can move and click. A hardware/timing limit, not a logic bug.

### Takeaways

- Read the challenge description as a specification: "upload your score file for evaluation" is a statement about where the flag lives. When a challenge names an artifact, that artifact is the target.
- Run `strings` before decompiling anything — two plaintext strings in `.rdata` (`BRUNNER-AIM-1`, `BrunnerAimTrainer-static-key`) were the entire crypto story for the file that actually mattered.
- Elaborate protection is often a moat, not a gate. A custom VM and nine layers of anti-debug wrapping a program whose output is validated server-side means the protection is guarding the wrong thing — ask what the protected component actually controls before committing to breaking it.
- When output is validated elsewhere, reverse the serializer, not the loader — the useful questions are "what format does it write?" and "what does the checker verify?"
- Follow a choke point through to the patch. Correctly identifying that all anti-debug funnels through one function is only useful if the next thought is "so stub it and move on."
- Decode magic constants from bytes on disk, not from a decompiler's immediate — little-endian u64 literals are easy to transcribe backwards.
