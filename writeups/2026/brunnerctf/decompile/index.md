# Decompile?

- Category: rev
- Difficulty: Easy

`vault` ("BRUNNER ONBOARDING VAULT (tm) v1.0") is a self-documenting crackme — it literally prints its own solving instructions on launch:

```
Welcome to the team! Before you may receive your
badge, please answer 5 simple onboarding questions.

Two tools will help get you through all five:
  1. strings ./vault
  2. A decompiler
```

Five questions, five independent checks, no algorithmic trickery — every answer is a literal constant sitting in `main`. It's a pure "can you read decompiled output correctly" exercise rather than a "can you invert a transform" one.

### Solution:

##### 1. Question 1 — password

```c
ask("  password> ", &var_58, 0x40);
if (strcmp(&var_58, "Pl4nt3xt_p455w0rd_1s_bu551ng"))
    wrong(...);
```

Direct string comparison against a literal — the `strings ./vault` hint confirms this one doesn't even need a decompiler.

**Answer:** `Pl4nt3xt_p455w0rd_1s_bu551ng`

##### 2. Question 2 — staplers

```c
uint64_t rax_3 = strtol(&var_58, 0, 0);
if (rax_3 != 0xfef)
    wrong(...);
```

The decompiler displays the constant as hex (`0xfef`), but `strtol(..., 0, 0)` with base `0` auto-detects the input's base from its prefix — no `0x` prefix means it parses as decimal. `0xfef` = `4079`.

**Answer:** `4079`

##### 3. Question 3 — asset tag

```c
uint64_t rax_6 = strtol(&var_58, 0, 0);
if (rax_6 != 0x2a)
    wrong(...);
```

Same `strtol` pattern as Q2, but here typing the value with its `0x` prefix works fine too, since base `0` auto-detects it.

**Answer:** `0x2a` (or `42` — both parse to the same value)

##### 4. Question 4 — mug letter

```c
ask("  letter> ", &var_58, 0x40);
if (var_58 != 0x42 || var_57)
    wrong(...);
```

`var_58` is the first byte typed; `var_57` is the byte right after it, which must be `0` — the input has to be exactly **one** character before the null terminator. `0x42` in ASCII is `'B'`.

**Answer:** `B`

##### 5. Question 5 — budget

```c
int64_t rax_16 = strtol(&var_58, 0, 0) * 2;
if (rax_16 != 0x5dc)
    wrong(...);
```

The input is transformed before the compare, so work backwards: `0x5dc` = `1500`, transform is `×2`, so the required input is `1500 / 2 = 750`.

**Answer:** `750`

##### 6. Assemble the flag

All five validated values get concatenated directly into the final `printf`:

```c
printf("  brunner{%s_%ld_0x%lx_%c_%ld}\n",
       &badge_password, badge_staplers, badge_asset_tag,
       (uint64_t)(int32_t)badge_mug_letter, badge_budget);
```

Substituting in the five recovered values:

**Flag:** `brunner{Pl4nt3xt_p455w0rd_1s_bu551ng_4079_0x2a_B_750}`

### Takeaways

- Not every "reversing" challenge needs an inversion algorithm — sometimes the whole job is locating the right constant in the decompiled output and correctly converting its base (hex vs. decimal) to match what the program expects as *input* versus how the decompiler *displays* it.
- `strtol(..., 0, 0)` with base `0` auto-detects `0x`-prefixed input as hex and everything else as decimal — worth remembering whenever a challenge's hex constant needs typing back in as plain decimal.
- Always check for a second byte/length constraint after a single-char comparison (`var_57` here) — an off-by-one on "how many characters did I actually send" is an easy way to get stuck on an otherwise trivial check.
- Working backwards through a simple transform (`×2`, `+`, XOR, etc.) applied to *your input* before the compare is a smaller-scale version of the same inversion technique used in more complex crackmes — the scale differs, the method doesn't.
