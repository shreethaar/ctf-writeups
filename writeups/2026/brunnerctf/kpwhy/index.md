# KPWhy

- Category: rev
- Difficulty: Medium

`kpiman` ("BrunnerCorp KPIman v3.1") reads an employee ID from stdin and runs it through three checks. Pass all three and it prints a promotion code — the flag.

### Solution:

##### 1. Map the checks

`main()` reads a line into a buffer, strips the newline, and rejects anything that isn't exactly 44 (`0x2c`) bytes. It then calls three validators and requires their return values to sum to `3`:

```c
if (strlen(&buf) == 0x2c) {
    int32_t rax_7  = calculateSynergy(&buf);
    int32_t rax_8  = measureVelocity(&buf);
    int32_t rax_12 = assessAlignment(&buf) + rax_7 + rax_8;

    if (rax_12 == 3)
        printf("Promotion code: %s\n", &buf);
}
```

Each validator loops over its byte range and `break`s out to `return 0` on the first mismatch — if the loop runs to completion instead, it falls through to `return 1`. So the *fallthrough* path is success, not the break path — easy to get backwards.

| Function | Bytes checked | Check type |
|---|---|---|
| `calculateSynergy` | `buf[0..14]` (15 bytes) | XOR against `kpi_alpha[]` with a per-index key |
| `measureVelocity` | `buf[15..29]` (15 bytes) | adjacent-byte sum against `kpi_beta[]` |
| `assessAlignment` | `buf[30..43]` (14 bytes) | substitution through `synergy_table[]` against `kpi_gamma[]` |

Each stage covers a disjoint slice, so all three can be solved independently and concatenated.

##### 2. Invert stage 1 — XOR

```c
buf[i] ^ ((i << 3) - i + 0x2a) == kpi_alpha[i]
```

XOR is its own inverse: `buf[i] = kpi_alpha[i] ^ ((i << 3) - i + 0x2a)`.

##### 3. Invert stage 2 — additive chain

```c
buf[i] + buf[i-1] == kpi_beta[i-15]      // mod 256
```

Seeded by `buf[14]` from stage 1, solved forward one byte at a time: `buf[i] = kpi_beta[i-15] - buf[i-1] (mod 256)`.

##### 4. Invert stage 3 — substitution table

```c
synergy_table[buf[i]] == kpi_gamma[i-30]
```

Built the inverse mapping (`output byte -> input byte`) by scanning `synergy_table` once. It turned out to be injective across the 14 needed targets — exactly one candidate per position, no branching needed.

##### 5. Extract constants and solve

Pulled `kpi_alpha`, `kpi_beta`, `kpi_gamma`, and `synergy_table` from `objdump -s -j .rodata kpiman`, then ran all three inversions:

```python
kpi_alpha = bytes.fromhex("48434d5128282620" "1b590505" "21eefc")[:15]
kpi_beta  = [0xa1,0xa4,0xd2,0xc0,0xd3,0xa5,0x92,0xcd,
             0x9e,0xa4,0xd3,0xcb,0x9c,0x60,0x9b]
kpi_gamma = bytes.fromhex("d3c06bee6bea6dee5d08dcdc8390")
synergy_table = bytes.fromhex("<256 bytes from .rodata>")

buf = bytearray(44)

# Stage 1: XOR inversion
for i in range(15):
    key = ((i << 3) - i + 0x2a) & 0xFF
    buf[i] = kpi_alpha[i] ^ key

# Stage 2: additive chain
for i in range(15, 30):
    buf[i] = (kpi_beta[i - 15] - buf[i - 1]) & 0xFF

# Stage 3: table inversion
inv = {}
for x in range(256):
    inv.setdefault(synergy_table[x], []).append(x)
for i in range(30, 44):
    buf[i] = inv[kpi_gamma[i - 30]][0]

print(bytes(buf).decode())
```

```
brunner{y0ur_kp1s_ar3_n0t_l00king_gr8_buddy}
```

##### 6. Bonus — the angr route

Manual inversion was faster, but this is also a legitimate angr target with two real gotchas:

- **`fgets` must be hooked correctly.** A `SimProcedure` writing the 44 symbolic bytes needs to also leave the `\n` *and* a trailing `NUL`, matching what real `fgets` does — skip the NUL and `strlen`/`strcspn` run into uninitialized memory, so the `strlen(buf) == 0x2c` gate fails deterministically before the solver gets a chance.
- **Path explosion.** 44 chained per-byte comparisons across three loops means angr forks ~2^44 states by default. `angr.exploration_techniques.Veritesting()` merges branches back at each block boundary — without it the process gets OOM-killed before reaching the target.

```python
import angr, claripy

proj = angr.Project("./kpiman", auto_load_libs=False)
BUF_LEN = 44
sym_bytes = [claripy.BVS(f"b{i}", 8) for i in range(BUF_LEN)]

class FakeFgets(angr.SimProcedure):
    def run(self, s, size, stream):
        for i, b in enumerate(sym_bytes):
            self.state.memory.store(s + i, b)
        self.state.memory.store(s + BUF_LEN, claripy.BVV(0x0A, 8))      # '\n'
        self.state.memory.store(s + BUF_LEN + 1, claripy.BVV(0x00, 8))  # NUL
        return s

class FakeStrcspn(angr.SimProcedure):
    def run(self, s, reject):
        return BUF_LEN   # the newline we placed is always the first match

proj.hook_symbol("fgets", FakeFgets())
proj.hook_symbol("strcspn", FakeStrcspn())

state = proj.factory.entry_state(add_options={
    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
})
for b in sym_bytes:
    state.solver.add(b >= 0x20, b <= 0x7E)  # printable ASCII only

simgr = proj.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.Veritesting())

FOUND_ADDR = 0x4013d3   # "Promotion code: %s\n" call site
AVOID_ADDRS = [0x401369, 0x401419]   # the two failure printf sites
simgr.explore(find=FOUND_ADDR, avoid=AVOID_ADDRS)

found = simgr.found[0]
print("Flag:", found.solver.eval(claripy.Concat(*sym_bytes), cast_to=bytes))
```

With both fixes in place this recovers the same flag directly via `simgr.found` — worth reaching for whenever `synergy_table`-style checks turn out *not* to be a clean bijection, where manual inversion would need to branch on multiple candidates per position.

**Flag:** `brunner{y0ur_kp1s_ar3_n0t_l00king_gr8_buddy}`
