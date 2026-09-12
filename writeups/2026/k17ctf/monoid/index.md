# monoid

- Category: rev

"There's this really cool fractal I like, but someone encrypted its parameters, even worse they wrote it in haskell, find the parameters to get the flag; glhf"

No binary ships with this one. The handout is a GHC `-ddump-simpl` / `-ddump-asm` pair plus the program's own output, so the reversing target is Core — Haskell with the sugar stripped out and every name fully qualified, which is far more readable than the "even worse they wrote it in haskell" framing suggests.

### Solution:

##### 1. Three modules, and only one matters

```
$ grep -n "Compiling" Main.dump-simpl
1:[1 of 4] Compiling Decode           ( Decode.hs, Decode.o )
242:[2 of 4] Compiling Fractal          ( Fractal.hs, Fractal.o )
489:[3 of 4] Compiling Main             ( Main.hs, Main.o )
```

`Fractal` is just an ASCII Julia renderer over the palette `" .-:=+*#%@"`; `out.txt` is its output. The parameters come out of `Decode`, driven from `Main`.

##### 2. Decode is a repeating-key XOR with a shift

Three definitions, verbose but mechanical once the qualified names are dropped:

```haskell
xorChar a b    = chr (ord a `xor` ord b)
unsubsChar a   = chr ((ord a - 67) `mod` 128)
decipher ct key
  | null key  = error "boop"
  | otherwise = zipWith (\c k -> unsubsChar (xorChar k c)) ct (cycle key)
```

`fromHex` is the obvious pairwise `readHex`, with `error "thats not how to fill a burito !"` on odd length. So `plain[i] = ((ct[i] XOR key[i mod len]) - 67) mod 128` — no key recovery needed, the key is a literal.

##### 3. The flag is the argument `Main` throws away

`main` deciphers a blob, `words` it, and destructures the result:

```haskell
main = writeFile "out.txt" $
         (\(a,b,c,d,e) -> renderJulia a b c d e) $
         case words (decipher (fromHex "2d5509...0f56") "#!s3kur1ty") of
           (_ : real : imag : max_iter : width : height : []) ->
             (read real, read imag, read max_iter, read width, read height)
           _ -> error ""
```

Core spells the discard out explicitly — the head binder is marked dead and never referenced again:

```
case words (decipher ...) of {
  [] -> jump fail_d2nY GHC.Internal.Types.(##);
  : _ [Occ=Dead] ds_d2nQ ->                     -- <- word 0 dropped here
```

Six words go in, five are used. The one that is pattern-matched into `_ [Occ=Dead]` is the flag; the encrypted blob was never about hiding the *parameters* at all.

##### 4. Decrypt

```python
pt = "".join(chr(((c ^ KEY[i % len(KEY)]) - 67) % 128) for i, c in enumerate(CT))
flag, real, imag, max_iter, width, height = pt.split()
```

```
$ ./solve.py
FLAG: K17{a_M0NaD_1s_4_M0n0Id_1n_th3_c4t3gORy_0f_3Nd0FuNC70r5}
params: c = -0.745643887 + 0.113825904i, maxIter=180, 96x32
out.txt reproduced exactly: True
```

The last line is the check that the plaintext is really the program's input and not just something flag-shaped: `out.txt` is 32 lines of 96 characters, matching `width`/`height`, and re-running `renderJulia` with the recovered constants reproduces it byte for byte.

```haskell
-- Fractal.renderJulia, reassembled from Core
zx = -1.8 + 3.6 * fromIntegral x / fromIntegral (width - 1)
zy = (-1.0 + 2.0 * fromIntegral y / fromIntegral (height - 1)) * 0.5
go n z | magnitude z > 2.0   = n
       | n >= maxIter        = n
       | otherwise           = go (n+1) (z*z + c)
palette !! min (length palette - 1) (go 0 (zx :+ zy) * length palette `div` (maxIter + 1))
```

Full script: [solve.py](solve.py)

**Flag:** `K17{a_M0NaD_1s_4_M0n0Id_1n_th3_c4t3gORy_0f_3Nd0FuNC70r5}`

### Takeaways

- A GHC Core dump is a *better* handout than a stripped binary. Every top-level name survives, string literals appear verbatim as `unpackCString# "..."#`, and the `-ddump-asm` file is never needed.
- `[Occ=Dead]` on a pattern binder is the Core equivalent of a dead store, and it is worth grepping for directly. Here it marks the one field of the decrypted record that the program computes and then deliberately ignores — which is exactly where the flag was put.
