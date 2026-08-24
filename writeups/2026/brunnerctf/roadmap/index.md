# Roadmap

- Category: rev
- Difficulty: Medium
- Author: Quack

Every request at Brunnerne Inc.™ now flows through an "Edge Roadmap Router" — only stakeholders who follow the approved roadmap reach the internal dashboard.

This one's an unusual rev challenge: there's no binary to disassemble at all. We're handed a Docker setup for a stock `nginx:1.31.3-alpine` server plus two config files, and the "reversing" is entirely static analysis of nginx's `map` directive being (ab)used to build an obfuscated validator/state-machine out of pure config. The flag is the URL path that satisfies it.

### Solution:

##### 1. Recon

We're given a Docker setup for plain `nginx:1.31.3-alpine` — `compose.yaml`, `Dockerfile`, `default.conf` (the "router"), and `roadmap-badges.conf` (an nginx `map` snippet). No binary anywhere. The nginx config itself is the puzzle: the flag is encoded as validation logic in `default.conf`, and the "correct" input is a URL path that satisfies it.

##### 2. The badge table

`roadmap-badges.conf` is a plain substitution table, single characters mapped to two-hex-digit "badges":

```nginx
default "zz";
"a" "7f";
"b" "59";
"c" "2e";
...
"_" "f5";
"{" "34";
"}" "3d";
```

This gets `include`d elsewhere to turn request characters into opaque tokens.

##### 3. Path extraction and length gate

```nginx
map $uri $route { default ""; "~^/(?<s>.*)$" $s; }
map $route $route_len_ok { default 0; "~^.{41}$" 1; }
```

`$route` is everything after the leading `/`; `$route_len_ok` is `1` only if it's exactly **41 characters**.

##### 4. Waypoints and badges

Two more phases pull the path apart and re-encode it:

```nginx
map $route $wp_8f96 { default ""; "~^.{8}(?<c>.)" $c; }
map $route $wp_fd17 { default ""; "~^.{3}(?<c>.)" $c; }
...
map $wp_8100 $badge_2bae { include roadmap-badges.conf; }
map $wp_fd17 $badge_f640 { include roadmap-badges.conf; }
...
```

There are 41 `wp_XXXX` variables, one per index of `$route`, each capturing a single character at a fixed but shuffled offset — the hex suffix on the variable name is an arbitrary label, not the position; only the `~^.{N}(?<c>.)` regex tells you which offset each one grabs. Each `wp_XXXX` is then run through the badge table to become a 2-hex-digit `badge_XXXX`.

##### 5. The state machine

The actual gate is a chain of ~40 `map` directives shaped like:

```nginx
map "${cp_d033}:${badge_8230}" $cp_9c1c { default "DETOUR"; "chk_7a06:f5" "chk_8eec"; }
```

This concatenates the *current* state with one character's badge and looks up the pair — since `$cp_d033` only ever equals `"DETOUR"` or one specific `chk_XXXX` value, the entry only matches when the previous check already succeeded **and** this position's badge equals a specific hex value. That's how `map`, which only does single-key lookups, fakes an AND of "previous state matched" + "this character matched". Chained together, ~40 of these form a linked list of character checks — `if route[i] != c: reject`, repeated 41 times, with the order scrambled and variable names hashed.

There's exactly one entry point with no dependency on a prior state, and exactly one exit that produces `"CLEARED"`:

```nginx
map $badge_a8e4 $cp_8a32 { default "DETOUR"; "0a" "chk_f6ca"; }
...
map "${cp_1be7}:${badge_6680}" $cp_199f { default "DETOUR"; "chk_3a12:0a" "CLEARED"; }
```

```nginx
map $cp_199f $reached_cleared { default 0; "CLEARED" 1; }
map "$reached_cleared$route_len_ok" $access { default 0; "11" 1; }
```

`$access` is `1` only if the length is exactly 41 **and** every character in the chain matched — the URL path itself *is* the flag.

##### 6. Solve programmatically

41 hashed variable names and a shuffled state chain are too error-prone by hand — parse and walk it instead: build the badge table, recover each `wp_XXXX`'s position from its regex, map `badge_XXXX -> wp_YYYY`, parse every `cp_XXXX` transition into `(dep_cp, badge, required_prevstate, required_hex, newstate)`, then walk the chain from the one entry point until hitting `"CLEARED"`.

```python
import re

conf = open('default.conf').read()
badges = open('roadmap-badges.conf').read()

char2hex = {m.group(1): m.group(2)
            for m in re.finditer(r'"(.)" "([0-9a-f]{2})";', badges)}
hex2char = {v: k for k, v in char2hex.items()}

wp_pos = {m.group(1): int(m.group(2))
          for m in re.finditer(
              r'map \$route \$wp_(\w+) \{ default ""; "~\^\.\{(\d+)\}\(\?<c>\.\)" \$c; \}',
              conf)}

badge_wp = {m.group(2): m.group(1)
            for m in re.finditer(
                r'map \$wp_(\w+) \$badge_(\w+) \{ include roadmap-badges\.conf; \}',
                conf)}

transitions = {}
for m in re.finditer(
        r'map "\$\{cp_(\w+)\}:\$\{badge_(\w+)\}" \$cp_(\w+) \{ default "DETOUR"; '
        r'"([^:]+):([0-9a-f]{2})" "(\w+)"; \}', conf):
    dep_cp, badge, cp_c, prevstate, hexval, newstate = m.groups()
    transitions[cp_c] = dict(dep_cp=dep_cp, badge=badge,
                              prevstate=prevstate, hex=hexval, newstate=newstate)

for m in re.finditer(
        r'map \$badge_(\w+) \$cp_(\w+) \{ default "DETOUR"; "([0-9a-f]{2})" "(\w+)"; \}',
        conf):
    badge, cp_c, hexval, newstate = m.groups()
    transitions[cp_c] = dict(dep_cp=None, badge=badge,
                              prevstate=None, hex=hexval, newstate=newstate)

dep_index = {}
for cp_c, v in transitions.items():
    if v['dep_cp'] is not None:
        dep_index.setdefault(v['dep_cp'], []).append(cp_c)

entry = next(k for k, v in transitions.items() if v['dep_cp'] is None)

route = ['?'] * 41
cur = entry
while True:
    v = transitions[cur]
    route[wp_pos[badge_wp[v['badge']]]] = hex2char[v['hex']]
    if v['newstate'] == 'CLEARED':
        break
    cur = next(c for c in dep_index[cur]
               if transitions[c]['prevstate'] == v['newstate'])

print(''.join(route))
```

This reconstructs the full 41-character path in one shot, retrieved by requesting it directly against the service:

```
GET /brunner{c0rp0r4t3_r04dm4p_t0_ng1nx_h34rt}
```

**Flag:** `brunner{c0rp0r4t3_r04dm4p_t0_ng1nx_h34rt}`

### Takeaways

- nginx's `map` directive is Turing-tarpit-flavored enough to build an entire obfuscated validator/state-machine out of it — no application code, backend, or scripting required.
- The obfuscation is purely nominal: hashed variable names and a shuffled check order. None of it is cryptographic, so static analysis (parse + graph-walk) fully recovers the answer without ever running the server.
- The `"${state}:${value}"` string-concatenation trick is the key pattern to recognize — it's how `map` fakes an AND of "previous state matched" and "this character matched" using only single-key lookups.
