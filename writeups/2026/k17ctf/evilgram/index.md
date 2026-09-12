# Evilgram

- Category: rev

"Evilgram is home to some of the most devious villains and evildoers. We've managed to hack into a suspects account, but we can't seem to find any proof of wrongdoing. They've sent some weird changing messages to known criminals but we haven't had any luck deciphering them. Can you help us crack the case?"

The handout is a static snapshot of a chat client. One message in it is a Plotly voxel animation, and another chat contains the encoder that produced it — a message encoded as the transition table of a reversible 3D cellular automaton. The animation ships 128 full state dumps of that automaton, which is enough to read the table straight back out.

### Solution:

##### 1. The "weird changing message" is 128 animation frames

`evilgram.html` is 300 KB, almost all of it one Plotly `mesh3d` trace in the John Wick chat. The frames are attached after the initial plot:

```javascript
Plotly.newPlot("157116db-...", [{"color":"#914EE9", ... "type":"mesh3d"}], ...)
  .then(function(){ Plotly.addFrames('157116db-...', [{"data":[{"x":[...],"y":[...],"z":[...]}]}, ...
```

`updatemenus` gives it Play/Pause buttons, and `scene.xaxis.range` is `[0, 4]` — so it is a 4x4x4 grid animating over time, not a static model.

##### 2. The LIVECon group chat leaks the encoder

The same page carries the generator in a `<pre>`, posted by "John Wick" with the note *"I've removed the validation part for security but here's the rest"* — which is why `RULESET_INVALID` is defined and never used. Two halves matter.

The message becomes a permutation of 0..255 via a factorial number system:

```python
def encode_msg_to_ruleset(msg):
    msg_num = int.from_bytes(msg.encode('utf-8'), 'big')
    if msg_num >= math.factorial(256):
        print("Flag too long (~210)")
        exit(1)
    factoradic = []
    for i in range(256):
        msg_num, rem = divmod(msg_num, i+1)
        factoradic.append(rem)
    factoradic.reverse()
    l = list(range(256))
    ruleset = []
    for skip_count in factoradic:
        ruleset.append(l.pop(skip_count))
    return ruleset
```

That permutation is then the rule table of a block cellular automaton on a Margolus neighbourhood — each step partitions the grid into 2x2x2 blocks, offset by the low three bits of the step counter, reads each block as an 8-bit state, and replaces it wholesale:

```python
for z in range(zSize >> 1):
    for y in range(ySize >> 1):
        for x in range(xSize >> 1):
            blockState = calcBlockState(map, x*2 + (step&1), y*2 + ((step&2)!=0), z*2 + ((step&4)!=0))
            nextBlockState = rules[blockState]
            setBlockState(map, x*2 + (step&1), y*2 + ((step&2)!=0), z*2 + ((step&4)!=0), nextBlockState)
```

`generateHist` runs that 128 times on a 4x4x4 grid, recording the grid *before* each step, and `gen_plotly` renders every recorded grid as one animation frame.

##### 3. Why the animation is the plaintext

Because the rule table is a permutation, the automaton is reversible — which is the property the comment *"Make sure your message is reversible before sending"* is checking for. But reversibility is not the leak. The leak is that every frame is a complete dump of the grid, and a 4x4x4 grid is exactly 8 blocks per step. So each consecutive pair of frames hands over 8 `(state -> next state)` pairs for free, and 127 transitions give 1016 samples of a 256-entry table:

```python
for step in range(1, len(grids)):
    before, after = grids[step - 1], grids[step]
    for z in range(2):
        for y in range(2):
            for x in range(2):
                X = x * 2 + (step & 1)
                Y = y * 2 + (1 if step & 2 else 0)
                Z = z * 2 + (1 if step & 4 else 0)
                b, a = block_state(before, X, Y, Z), block_state(after, X, Y, Z)
                assert rules.get(b, a) == a, "inconsistent transition"
                rules[b] = a
```

1016 samples over 256 slots leaves roughly `256 * e**-4` ~ 5 entries unseen on average, which would have meant a small brute force over the leftovers. This particular history happens to cover all of them:

```
frames: 128
known rules: 256 conflicts: 0
missing inputs: []
missing outputs: []
```

Recovering the grids from the frames needs one detail: `build_voxel_mesh` emits 8 cube vertices per live voxel and `pad_vertices` pads the trace with all-zero groups, so a padded group and a real voxel at the origin have to be told apart. They differ — a real voxel at `(0,0,0)` still has 8 *distinct* vertices, a padded one has 8 copies of `(0,0,0)`.

##### 4. Invert the Lehmer code

With the full permutation in hand the encoder runs backwards: the position each value was popped from is its Lehmer digit, undo the `reverse()`, then fold the factoradic back into an integer.

```python
pool, lehmer = list(range(256)), []
for v in ruleset:
    lehmer.append(pool.index(v))
    pool.remove(v)
factoradic = lehmer[::-1]

n = 0
for i in range(255, -1, -1):
    n = n * (i + 1) + factoradic[i]
msg = n.to_bytes((n.bit_length() + 7) // 8, "big").decode()
```

```
$ ./solve.py
please i NEED the kfc recipe ASAP my local kfc closed down and I NEED MY CHICKEN K17{y0u_Th0ug5t_W3_w3Re_Ev1l_bUt_re4llY_we_are_JuSt_m4ss1ve_cH1cken_l0vers_w1th_a_huge_Hung3r_anD_n0th1ng_cAn_sT4nD_1n_OuR_way!!}
```

The plaintext is the whole message, flag included — the villainous conspiracy turns out to be a fried chicken recipe request.

Full script: [solve.py](solve.py)

**Flag:** `K17{y0u_Th0ug5t_W3_w3Re_Ev1l_bUt_re4llY_we_are_JuSt_m4ss1ve_cH1cken_l0vers_w1th_a_huge_Hung3r_anD_n0th1ng_cAn_sT4nD_1n_OuR_way!!}`

### Takeaways

- Encoding a secret as a *transition table* only hides it while the transitions stay private. Shipping an animation of the automaton running is shipping labelled training data for the table, one row per block per step — and a small grid makes it worse, not better, because every step touches every cell.
- The factoradic/Lehmer step is a bijection from integers to permutations of 0..255, so it neither adds nor destroys entropy. It looks like encryption and is really just a base change; recovering the permutation recovers the message exactly.
- Worth checking the coverage arithmetic before assuming a full recovery: `n` samples over a 256-slot table leave about `256 * e**(-n/256)` entries unseen. At 1016 samples that is ~5 unknowns, cheap to brute force against a "decodes to ASCII" oracle — this run simply got lucky and needed none.
