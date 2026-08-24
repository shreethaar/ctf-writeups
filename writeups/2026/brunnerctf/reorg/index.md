# Reorg

- Category: rev
- Difficulty: Hard
- Author: Quack

Sequel to [Roadmap](../roadmap/): Brunnerne Inc.™ has flattened the org chart, twice. Requests now escalate through a chain of managers who each review a different metric, and nobody remembers who approves what anymore — find the escalation path that gets signed off all the way to the top.

Same core idea as Roadmap — the nginx config *is* the puzzle, the URL path *is* the flag — but with several more layers of indirection and deliberate decoy branches stacked on top, so Roadmap's straightforward path-tracing approach doesn't work unmodified.

### Solution:

##### 1. Recon — five extra ingredients vs Roadmap

Same `$route`/`$route_len_ok` length gate as Roadmap (now 40 chars) and the same `seat_XXXX` → `band_XXXX` per-position-to-badge pipeline. Three new files add plain single-char substitution tables (`reorg-legal.conf`, `reorg-sales.conf`, `reorg-ops.conf`), each a bijection over the same 39-symbol badge alphabet — purely cosmetic extra relabeling layered on top of a `band_XXXX`/`ledger_XXXX` value.

The real new ingredient is `reorg-ledger.conf` — a **keyed** substitution, 1521 entries of the form `"XY" -> Z` (for every pair of badge characters `X,Y`, an output `Z`; for fixed `X` the 39 rows form a bijection). It backs a **running accumulator**: one seed node from `$route_len_ok`, then every other `ledger_XXXX` is `new = table[prev_ledger_char][this_band_char]`:

```nginx
map $route_len_ok $ledger_d1d8 { default "!"; "1" "Q"; }
...
map "${ledger_5f6f}${band_4f3c}" $ledger_4b65 { include reorg-ledger.conf; }
```

Following the `prev → cur` pointers forms **one single 31-node chain** (30 hops) from the seed — a CRC-like value folding in one character at a time, not a tree.

##### 2. The state machine, with decoys

Roadmap's `cp_XXXX` chain had exactly one live entry per state. Reorg uses two maps per level — a **selector** that picks which checkpoint to consult (a `band_`, `ledger_`, or `legal`/`sales`/`ops`-wrapped one) based on the current tier, and a **transition** that requires that checkpoint's value to equal one specific literal for that state, else it collapses to `"REJECTED"`:

```nginx
map $tier_44e8 $review_cde4 {
    default $ops_811a;
    "mgr_ec4d" $ops_811a;
    "mgr_89a8" $ledger_a443;
    "mgr_fcee" $sales_18ba;
}
map "${tier_44e8}:${review_cde4}" $tier_01c8 {
    default "REJECTED";
    "mgr_ec4d:I" "mgr_b9f4";
    "mgr_fcee:R" "mgr_b9f4";
    "mgr_ec4d:U" "mgr_5b38";
    "mgr_ec4d:O" "mgr_5b38";
    ...
}
```

Two things make this harder than Roadmap. First, the entry state is only ever `"mgr_ec4d"` (seeded from `route_len_ok`), so transitions listed for `mgr_89a8`/`mgr_fcee` at level 1 are **unreachable decoys** that only reveal themselves once you track actual reachability. Second, a single reachable state can have **multiple valid `(literal → next_state)` edges** (`mgr_ec4d` has three: `I`, `U`, `O`) — genuine branching, not filtered noise, so it can't be resolved by reading one map at a time like Roadmap could. There are 40 such (selector, transition) pairs chained from the seeded entry to a final `tier_df0a`.

##### 3. The audits

Six more checks, independent of the tier chain, use nginx regex backreferences to force groups of positions to hold identical characters:

```nginx
map "${band_2dba}${band_785f}${band_d337}${band_69b5}${band_251b}" $audit_57ac {
    default 0; "~^(?<x>.)\k<x>\k<x>\k<x>\k<x>$" 1;
}
```

All six must hold, alongside `reached_cleared` and `route_len_ok`, for `$access`.

##### 4. Why naive tracing doesn't work here

In Roadmap, each hop pinned exactly one route character deterministically — no search required. Here, each level offers two candidate checkpoints depending on the current state, a state can have multiple valid literals (real branching), and `ledger_` checkpoints correspond to a point in a 30-hop accumulator chain that's only resolvable once its entire prefix back to the seed is known. Doing this by hand is impractical — needed a solver.

##### 5. Parse everything, then watch naive DFS fail

Regex out of `default.conf`: `seat_XXXX → position`, `band_XXXX → seat_XXXX`, the ledger seed and 30 `ledger_XXXX → (prev_ledger, band)` links, the 98 `legal/sales/ops_XXXX → (band|ledger)_YYYY` links, the 40 selector/transition map pairs, and the 6 audit constraints. Confirmed structurally: 40 seat positions, a *single* 31-node ledger chain (not a tree), 40 selector/transition pairs chaining linearly to `tier_df0a`.

A first solver attempt — branch on every valid `(literal, next_state)` at each level, prune only on direct route-position conflicts — stalled around level ~20 after millions of nodes. Most literal choices don't collide with anything yet, so there's nothing to prune early: the real disambiguating signal (the ledger chain and the audits) was only being checked at the very end.

##### 6. Add constraint propagation

The fix: maintain `ledger_known` (resolved chain values, seeded with `"Q"`) and `ledger_target` (pending required values) as first-class state, and after every new fact run a fixpoint pass that walks the ledger chain forward wherever `prev` is known and this hop's route position is already assigned, walks it *backward* wherever `prev` is known and a target is pending for `cur` (inverting the required `band` character directly out of that row of `reorg-ledger.conf`, immediately pinning a route position), and propagates the 6 audit equalities the same way:

```python
def propagate(assign, ledger_known, ledger_target):
    changed = True
    while changed:
        changed = False
        for cur, (prev, band) in ledger_dep_list:
            if cur in ledger_known:
                continue
            pos = seat_pos[band_seat[band]]
            if prev in ledger_known and pos in assign:
                val = ledger_rows[ledger_known[prev]][bands[assign[pos]]]
                if cur in ledger_target and ledger_target[cur] != val:
                    return False
                ledger_known[cur] = val; changed = True
            elif prev in ledger_known and cur in ledger_target:
                target = ledger_target[cur]
                bandchar = ledger_rows_rev[ledger_known[prev]].get(target)
                if bandchar is None:
                    return False
                ch = rev_bands.get(bandchar)
                if ch is None:
                    return False
                if pos in assign and assign[pos] != ch:
                    return False
                assign[pos] = ch
                ledger_known[cur] = target
                changed = True
        for positions in audit_positions:               # equality groups
            vals = set(assign[p] for p in positions if p in assign)
            if len(vals) > 1:
                return False
            if len(vals) == 1:
                for p in positions:
                    if p not in assign:
                        assign[p] = next(iter(vals)); changed = True
    return True
```

Because the tables are all bijections, most "ledger" checkpoints become immediate forced position assignments (the chain mostly gets checked in roughly the order it's built), collapsing the branching dramatically. The outer search is a straightforward backtracking DFS over the 40 levels: at each level, resolve the active checkpoint for each candidate literal, run `propagate`, recurse on success, backtrack on conflict. With propagation in place, the search finds the accepting path in ~3,500 nodes and terminates in well under a second.

##### 7. Verify independently, get the flag

Wrote a second, completely separate script that re-implements the nginx semantics directly — build `seat`/`band`/`ledger` dicts from the candidate route, walk the 40-level `tier`/`review` chain literally following each map's rules, evaluate all 6 audits — and confirmed `$access` evaluates true end to end, reaching `CLEARED` at level 40.

```
GET /brunner{th3_n3w_m4n4g3r_1s_4n_ng1nx_m4p}
```

**Flag:** `brunner{th3_n3w_m4n4g3r_1s_4n_ng1nx_m4p}`

### Takeaways

- Same core trick as Roadmap (`map` directives compiled into a hidden validator), escalated two ways: an accumulator (`ledger`) that makes some checks depend on a *prefix of the input* rather than a single position, and genuine non-determinism (multiple valid edges per state) mixed with genuinely-dead decoy entries — you can't tell which is which without tracking reachability.
- The load-bearing realization: because every substitution table here is a **bijection**, every "must equal X" constraint can be inverted, and because the ledger forms one linear chain, most of those inversions cascade into immediate, forced route-character assignments. That's what makes brute force unnecessary — it's a propagation problem, not a search problem, once the tables are recognized as permutations.
- Plain backtracking without early constraint propagation is a classic trap: the state graph alone looks tractable (only ~3-4 live states per level), which makes it easy to assume DFS will "just work" — but without propagating the ledger/audit constraints as soon as possible, the branching still compounds past anything brute-forceable in reasonable time.
- Always cross-check a solver's output with an independent re-implementation of the target semantics before trusting it, especially when the solver itself contains custom, easy-to-get-subtly-wrong logic like the propagation fixpoint here.
