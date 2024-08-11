---
title: sh
layout: default
---

# sh 
Guess? 

- Challenge file: mis-sh.zip
- Category: misc
- Level: Normal 

Solution:

1. Analyze game.sh

```bash
#!/usr/bin/env sh

set -euo pipefail

printf "Can you guess the number? > "

read i

if printf $i | grep -e [^0-9]; then
    printf "bye hacker!"
    exit 1
fi

r=$(head -c512 /dev/urandom | tr -dc 0-9)

if [[ $r == $i ]]; then
    printf "How did you know?!"
    cat flag.txt
else
    printf "Nope. It was $r."
fi
```

Based on shell script, it is prone to command injection from `set -euo pipefail` and `printf $i` statement is vulnerable to command injection, as it doesn't properly sanitize the user input.


