---
title: AI? PRNG
layout: default
---

# AI? PRNG

- Category: rev
- Level: easy
- Description: I heard those tech cool buzz words use matrices. Well my (very legit) PRNG also uses matricies, can I slap AI/ML/Deep Learning on it too???? Unless???
- Challenge File: ai\_rnd and random\_numbers.txt

Solutions from: @N1k4

### Solutions: 

```py
import subprocess
from string import printable

def run(inp):
    if isinstance(inp, str):
        inp = inp.encode()
    p = subprocess.Popen(["./ai_rnd", "/dev/fd/0", "/dev/fd/1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, _ = p.communicate(inp)
    return stdout

dic = {}
for c in printable:
    dic.update({c: run(c*32).split()})

enc = b'a5 39 24 90 a8 a5 88 77 26 e4 3c 14 03 1e ba 3c 7d bb dc d6 aa 90 50 c9 0f aa dd 57 33 e1 a4 c7'

for i, c in enumerate(enc.split()):
    ans = [ch for ch, res in dic.items() if res[i] == c]
    if len(ans)==1:
        print(ans[0], end='')
    else:
        print(f'\n{ans}')
```


