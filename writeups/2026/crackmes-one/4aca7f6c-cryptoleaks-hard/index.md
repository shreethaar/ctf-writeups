---
title: "cryptoleaks (HARD)"
layout: default
---

# cryptoleaks (HARD)

"One is easy, and the other requires more creativity."

- Category: rev / crypto
- Difficulty: 3.0
- Challenge author: 4aca7f6c
- Challenge link: [crackmes.one](https://crackmes.one/crackme/60d8d7bd33c5d410b8843087)
- Platform: Linux x86-64 (ELF PIE, dynamically linked, stripped), needs AVX2 + RDRAND

The same binary as [EASY](../4aca7f6c-cryptoleaks-easy/), listening on its second port. It is still a TCP server that draws a fresh key from `RDRAND` per connection and then leaks a byte of AES state with every one of a thousand free encryptions — but the key is now 32 bytes, and the leak no longer comes from a fixed round. Half the hints describe the final round and half describe the one before it, and the round before the last sits behind MixColumns, which is what makes this side look like it needs a `2**32` search per column. It doesn't, because MixColumns is linear.

The reversing is shared with the EASY writeup — the server structure, the unterminated-buffer disclosure that puts the leak on the wire, and the page-offset trick that defeats PIE are all covered there. This one picks up at what changes when the round count goes to 14.

![Call graph of cryptoleaks: main spawns two accept-loop threads, each connection runs the challenge session that repeatedly encrypts and leaks, then the guess check branches to the WIN or LOSE sink](callgraph.png)

### Solution:

##### 1. What the mode flag actually changes

`main` starts both threads on the same accept loop with a mode byte, `0` for EASY on 19146 and `1` for HARD on 32620, and `sub_19d0` branches on it exactly twice — once to pull two more `RDRAND` words, and once to ask for a 32-byte key schedule:

```c
if (a1) {
  do { v17 = rdrand(); } while (!rdrandIsValid());
  do { v18 = rdrand(); } while (!rdrandIsValid());
  sub_2060(v5, &v4, 0x20);        // AES-256: 15 round keys, 14 rounds
} else {
  sub_2060(v5, &v4, 0x10);        // AES-128
}
```

`sub_2060` stores the round count at `rk + 0xf0` (`0xe` here) and `sub_20d0` passes it straight into the assembly core. The check at the other end widens to match: `sub_18c0` reads 64 hex characters instead of 32, decodes both halves, and `memcmp`s 32 bytes.

##### 2. A coin flip the EASY path never takes

The leak setup in `sub_1f5b` has a branch that AES-128 can't reach, because it's gated on the round count:

```c
v6 = 0;
do { v7 = rdrand(); } while (!rdrandIsValid());
v8 = v7;
if (0xc <= a2) { v8 = v7 >> 1 & 0x7f; v6 = v7 & 1; }   // 12 rounds or more
v9 = (unsigned long)(v8 & 0xf);                         // byte index 0..15
while (true) {
  a2 -= 1;
  *a1 = v1 ^ *a0;                                       // AddRoundKey
  if (a2 == v6) v9 = (*a1)[v9];                         // leak
  ...
}
return v9 + 0x3790;
```

With `a2 = 14` the branch is taken, so one random bit becomes `v6` and the index comes from the bits above it. Iteration `k` sees `a2 = 14 - k`, so the guard `a2 == v6` fires on:

- `v6 == 0` -> iteration 14, leaking the state entering the **final round** (the EASY case);
- `v6 == 1` -> iteration 13, leaking the state entering **round 13**.

Two populations, mixed 50/50, indistinguishable on the wire. That is the "more creativity" the description advertises.

##### 3. Round 14 first, through the noise

The final-round relation is unchanged from EASY — `ct[i] = SBOX[s14[SHUF[i]]] ^ rk14[i]`, so each round-14 hint votes `rk14[i] = ct[i] ^ SBOX[leak]` at the one index `i` with `SHUF[i]` equal to the leaked position. The round-13 half now contributes pure noise, halving the signal: at 1000 hints the correct byte lands ~31 times instead of ~62, against a noise mean of ~3.8.

That still separates cleanly (a Poisson(3.8) tail reaching 31 is a `3e-18` event, and there are only 255x16 chances to try), but it is cheap to sharpen. Vote once, keep only the hints consistent with a round-14 leak, and vote again on those:

```python
rk14 = vote(hints)
r14  = [h for h in hints if h[1] in state_last_round(h[0], rk14)]
rk14 = vote(r14)                       # now ~500 samples, all signal
```

##### 4. The two populations separate themselves

That filter is also the whole classifier. Once `rk14` is known, every hint yields the full 16-byte state entering the final round:

```
s14[SHUF[i]] = INV_SBOX[ ct[i] ^ rk14[i] ]
```

A round-14 leak is by definition one of those sixteen bytes. A round-13 leak is an unrelated value that only lands in the set by coincidence, with probability `1 - (255/256)**16`, about 6%. So:

- `leak in s14` -> almost certainly round 14 (used for stage 1);
- `leak not in s14` -> **certainly** round 13.

The second bucket is exactly clean, which is the one that matters — roughly 47% of hints, and no contamination at all in the direction that would corrupt the next stage.

##### 5. Round 13 looks like it costs 2**32 per column

Round 13 produces the state we just recovered:

```
s14 = MixColumns(ShiftRows(SubBytes(s13))) ^ rk13
```

and one byte of `s13` is what leaked. Inverting to reach `s13` means undoing the AddRoundKey with an unknown `rk13` and then undoing MixColumns — and InvMixColumns mixes four bytes at a time, so a byte of `s13` depends on four unknown bytes of `rk13`. Guessing a column is `2**32`, times four columns, times a few hundred samples. That is the wall the challenge is built around.

##### 6. ...but InvMixColumns is linear, so the key falls back out

InvMixColumns is a fixed matrix over GF(2^8), and matrix multiplication distributes over XOR. So there is no need to know `rk13` before undoing the mixing:

```
InvMC(s14 ^ rk13) = InvMC(s14) ^ InvMC(rk13)
```

Write `A = InvMC(s14)`, computable from data alone, and `K' = InvMC(rk13)`, a fixed 16-byte unknown. Then

```
ShiftRows(SubBytes(s13)) = A ^ K'
```

and reading that at the index `i` where `SHUF[i]` is the leaked position gives

```
K'[i] = A[i] ^ SBOX[leak]
```

which is **the identical byte-independent vote as the last round** — same code, same statistics, no search. Recover `K'` by counting, then push it back through the forward matrix to get the real round key:

```python
r13  = [(inv_mix_columns(state_last_round(ct, rk14)), leak)
        for ct, leak in hints if leak not in state_last_round(ct, rk14)]
rk13 = mix_columns(vote(r13))
```

The `2**32` per column evaporates because the unknown was never actually tangled with the data — the linear layer just made it look that way.

##### 7. Two round keys, because AES-256 needs two

AES-128 unwinds from a single round key, but AES-256's schedule consumes eight words per step (`w[i] = w[i-8] ^ f(w[i-1])`), so one 16-byte round key is only half a step and the recursion won't close. `rk13 || rk14` is `w52..w59` — eight words, exactly enough. Running `i` from 59 down to 8 keeps `w[i-1]` known at every step, and `w0..w7` is the key:

```python
for i in range(total - 1, nk - 1, -1):
    t = list(w[i - 1])
    if i % nk == 0:
        t = [SBOX[b] for b in t[1:] + t[:1]]
        t[0] ^= RCON[i // nk - 1]
    elif nk > 6 and i % nk == 4:          # AES-256's extra SubWord step
        t = [SBOX[b] for b in t]
    w[i - nk] = [w[i][j] ^ t[j] for j in range(4)]
```

Note the `i % nk == 4` case: AES-256 applies a bare `SubWord` midway through each step, and it exists only for `nk > 6`. Skipping it produces a key that looks fine and is wrong.

##### 8. Beating it

Against the pristine binary — no patching, no debugger, and the key freshly random on every connection:

```
$ python3 solve.py
[HARD] 127.0.0.1:32620
  800 hints, &sbox = 0x562f7a8cc790
  rk14 = cf1be8cd518d54b5cb489b0f489d423c (425 round-14 samples)
  rk13 = 8ea9d26a31891fd1ace34dd4ac53bb87 (375 round-13 samples)
  key  = bed7453ae9fe755bc7cfb0e775a1fe4388cc557562187ff25fa52e9839c0e9e5
  -> b'FLAG{4Ch15vem5nt_Unl0ck5d:_m1x_c0lumn5_Def54ted}'
```

Before submitting, the script checks the recovered key against every hint it saw: each leaked byte must appear either in the round-14 input or in the round-13 input that the key predicts. A key that merely won a vote can pass on luck; a key that explains all 800 leaks cannot. Sweeping the sample count puts the real threshold near 400 hints — twice EASY's, which is exactly the 50/50 split showing up in the budget:

```
[hard] 50:-- 100:-- 150:-- 200:-- 300:-- 400:OK 600:OK 800:OK 1000:OK
```

The server allows 1000 and spends 10 ms polling between them, so the attack finishes in under ten seconds, dominated entirely by waiting for hints.

**Flag:** `FLAG{4Ch15vem5nt_Unl0ck5d:_m1x_c0lumn5_Def54ted}`

### Takeaways

A linear layer never protects a key that is XORed after it. The whole difficulty of this side is the appearance that reaching round 13 requires guessing four bytes of `rk13` at once to invert a column of MixColumns. But `InvMC(s ^ k) = InvMC(s) ^ InvMC(k)`, so the unknown passes through untouched and comes out as a *different* unknown that is still XORed byte-for-byte with computable data. Recover the transformed key, then map it back. Any time an attack seems to require brute-forcing through a linear operation, push the operation onto the known side of the equation first — the flag's own text (`m1x_c0lumn5_Def54ted`) says this is the intended read.

Peel one round, and the next one becomes the same problem. The round-14 attack isn't just a step toward the key; it's what turns each ciphertext into a known intermediate state, which is what makes round 13 attackable at all. Layered leaks tend to unwind this way: solve the outermost, use it to compute deeper values, and check whether the deeper relation has the same shape. Here it was literally the same `vote()` function called twice.

Mixed leak populations can classify themselves once you have half the answer. The coin flip is invisible on the wire, but after `rk14` is known a round-14 leak must be one of sixteen recovered state bytes, while a round-13 leak only collides by accident about 6% of the time. Filtering on `leak not in s14` yields a bucket that is 100% round-13 — noise removed not by better statistics but by a consistency test the first stage handed over for free.

Verify against what the leak predicts, not against the vote that produced it. With a fresh random key per connection there is no fixed answer to check, and a majority vote will always return *something*. The usable invariant is that the recovered key must explain every observation — reconstruct both candidate round inputs for all 800 hints and confirm each leaked byte actually occurs. That converts "the histogram had a clear peak" into a statement that can genuinely fail.
