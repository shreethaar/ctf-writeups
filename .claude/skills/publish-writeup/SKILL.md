---
name: publish-writeup
description: |
  Converts raw CTF challenge notes (draft writeups, README hints, solve
  scripts, screenshots) from an arbitrary source folder into this repo's
  house writeup style, generates a curated call graph for rev/pwn
  targets, places them at writeups/<year>/<ctf>/<challenge>/,
  updates _data/navigation.yml and the CTF's index.md, commits locally,
  and asks for confirmation before pushing. Use whenever the user has
  solved a CTF challenge and wants their raw notes turned into a published
  writeup on shreethaar.github.io/ctf-writeups.
version: 1.1.0
---

# Publish a CTF writeup

Turns messy solve notes into a repo-styled writeup and gets it committed
(and, on confirmation, pushed).

## Inputs needed

Ask only for what's missing — infer the rest:

- **Source folder** — where the raw notes/solve script/screenshots live
  (e.g. `~/Desktop/ctf/<ctfname>/<category>/<challenge>/`).
- **CTF name** — e.g. `brunnerctf`. Match existing casing in `writeups/`
  if this CTF already has entries from a prior year; otherwise use
  whatever slug the source folder implies.
- **Year** — infer from the current date if not given. If the CTF folder
  already exists under a different year in `writeups/`, ask whether this
  is a new edition or a continuation before creating a new year folder.
- **Challenge name/slug** — infer from the source folder name.

## Step 1 — Read every raw source

Read all of it before writing anything: draft writeups (`WRITEUP.md`,
`NOTES.md`, etc.), the challenge's own `README.md`/prompt text, solve
scripts, and any screenshots. The challenge's README often states the
official **Category**, **Difficulty**, and challenge **Author** (the
setter, not the writer) — pull those if present. Do not guess them if
absent; omit the bullet instead of inventing a value.

## Step 2 — Rewrite in house style

Study 2-3 existing writeups under `writeups/` in the same category first
(e.g. `writeups/2025/brunnerctf/*/index.md`) to recalibrate tone —
don't rely on memory of the format. The shape is:

```markdown
# <Challenge Title>

- Category: <pwn/rev/crypto/web/forensics/misc>
- Difficulty: <if known>
- Author: <challenge setter, if known>

<1-3 sentence flavor blurb from the challenge prompt, if it has one. If
the challenge's *shape* is itself unusual for its category — e.g. a
"rev" challenge with no binary at all, or a "pwn" challenge that's pure
logic — add a sentence saying so and what the real puzzle turns out to
be. That context is worth more to future-you than flavor text alone.>

### Solution:

##### 1. <short step title>

<prose for this step, with its output/finding folded in, plus any
code/asm/output blocks that support it, using fenced blocks with a
language tag where sensible>

##### 2. <next deduction, building on 1>

...

**Flag:** `<the flag>`

### Takeaways

<optional — only include when the source notes have genuinely reusable
insight beyond this one challenge (a recognizable pattern, a gotcha
worth remembering next time, a technique that generalizes). Skip it for
routine challenges; don't manufacture takeaways just to fill the
section.>
```

Each step is its own `##### N. <title>` (h5) heading — not a markdown
numbered-list item — followed by that step's prose/code underneath.

Rules for the rewrite:

- Steps are a **chain of reasoning to the flag**, not a tool tutorial.
  Cut anything that teaches generic concepts the source notes included
  for a player who's never done pwn/rev before (e.g. "what pwntools is",
  "how to install a venv") — this repo's audience is the author's future
  self, not a beginner.
- Keep the technical substance: addresses, offsets, disassembly excerpts,
  the actual exploit/solve script logic, and *why* each step follows
  from the last.
- Prefer fewer, denser steps unless the challenge genuinely needs deep
  root-cause/mitigation analysis — check whether other writeups for the
  same CTF lean short or long, and match them.
- **This site builds with Jekyll/Liquid, which parses the raw file
  *before* Markdown/code-fence rendering — a literal `{%` or `{{` inside
  a fenced code block (a `printf` format string like `"flag{%s_%d}"`,
  a Jinja/Liquid snippet, etc.) is NOT protected by the triple-backtick
  fence and will throw a fatal `Liquid::SyntaxError` that breaks the
  *entire* GitHub Pages build for every page on the site, not just this
  one.** Grep the finished file for `{%` and `{{` before committing; if
  either appears inside a code block, wrap that block (or just the
  offending line) in `{% raw %}` / `{% endraw %}`:
  ```
  {% raw %}
  ```c
  printf("flag{%s_%d}\n", a, b);
  ```
  {% endraw %}
  ```
- End with the flag on its own bolded line. That is always the last
  line of the file.
- **If the source notes never actually land on a flag** (a post-mortem
  written up after the CTF ended, notes assembled from what other
  people shared in Discord, an exploit chain that was never fully run
  to completion) — don't fabricate one and don't force the flag line.
  Add a `- Status: Not solved live — <what happened>` bullet to the
  metadata block instead, credit whoever's solution is being described,
  and end the last step with the confirmed solution/reasoning rather
  than a `**Flag:**` line. Ask the user to confirm this framing (and
  whether a real flag exists to close it out properly) before writing —
  it's a real content decision, not a formatting default. On the CTF's
  `index.md`, list these separately from the "I managed to solve"
  list — e.g. under a "not solved live, written up from analysis /
  community solutions" heading — rather than implying a live solve.

## Step 3 — Add a call graph (rev / pwn challenges)

A picture of how execution moves through the binary is usually the
highest-value figure in a rev writeup: the reader gets the shape of the
program — entry, the checks, the win and lose sinks — before reading a
line of decompiled C. Add one whenever the challenge has more than two
or three interesting functions. Skip it when the whole thing is a
single `main`, or when nothing was reversed (crypto, web).

**Know which graph you're drawing** — these are different objects with
different tooling, and the words get used interchangeably:

- **Call graph** — nodes are *functions*, edges are calls. This is the
  one that answers "how does this program flow", and it's what belongs
  in almost every rev writeup.
- **Control-flow graph (CFG)** — nodes are *basic blocks within one
  function*, edges are branches. Worth including only when a single
  function is the whole puzzle (a VM dispatch loop, an obfuscated
  checker) and its internal branching is the point.

### Prerequisite

Graphviz does the layout and is needed either way. Check first — it is
often not installed:

```bash
dot -V || echo "install graphviz"        # Arch: sudo pacman -S graphviz
```

Installing needs a password, so ask the user to run it (`! sudo pacman
-S graphviz`) rather than attempting sudo.

### Generating it

The binary has to parse before either route works — repair a corrupted
header first, since a broken ELF stops r2 exactly as it stops a
decompiler.

**radare2 — fastest, one command:**

```bash
r2 -A ./challenge
> agCd > callgraph.dot         # whole-program call graph, DOT format
> agfd @ sym.check             # CFG of one function, DOT format
> q
dot -Tpng -Gdpi=140 callgraph.dot -o callgraph.png
```

**From the decompiler — when the labels need to match your analysis:**
`kuna decompile-all ./challenge --json` carries a `code` field per
function, so scanning each body for the names of other functions gives
the call edges, and you emit DOT yourself. More work, but you control
node text and styling, and it sees functions r2 misses (below).

### Cross-check before trusting it

`r2 -A` discovers functions by following cross-references, so a
function that nothing references is simply absent from its graph.
Compare counts (`kuna functions --json` against r2's `afl | wc -l`) and
chase any gap — an uncalled function is usually compiler-emitted dead
code, which is itself worth a sentence in the writeup.

Never ship an auto-generated graph unread. Tools label nodes by
address, not by behaviour, and a confidently mislabeled node teaches
the reader something false. Check every label against your own
analysis before committing the image.

### Make it readable

Raw `agCd` output is a hairball. Curate it:

- Drop libc/PLT nodes. Keep a single shared `exit` sink if every
  terminal path reaches one — that alone makes the structure legible.
- Label nodes with what the function *does* alongside its address
  (`sub_1a00 / 0x1a00 / parse key file`), never the address alone.
- Label edges with the condition that takes them ("bad length",
  "key == username").
- Number the path to success and colour it, so the reader's eye follows
  the winning route first.
- Distinguish the sinks: success, failure and rejection are different
  outcomes and should not look alike.

### Placing it in the writeup

- Put the image in the step where the functions it names have just been
  introduced, so no label is a forward reference — usually right after
  the step identifying the check and the win/lose paths.
- Render to **PNG** (`-Tpng -Gdpi=140`) and commit it alongside
  `index.md`, referenced relatively:
  `![Call graph of challenge](callgraph.png)`. Precedent for images
  living next to the writeup: `writeups/2026/crackmesone-ctf/`.
- Give it real alt text describing the graph, not "graph".
- **Do not commit the graph generator script.** Solve/exploit scripts
  belong in the repo (Step 4); a throwaway DOT emitter does not.
  Describe the pipeline in prose or a short shell block instead — and
  make sure the surrounding text doesn't then reference a file that was
  never shipped.

## Step 4 — Place files

- Writeup: `writeups/<year>/<ctf-slug>/<challenge-slug>/index.md`
  (create parent dirs as needed). Match the challenge-slug casing style
  already used for that CTF's other challenges in `navigation.yml` if
  any exist, otherwise lowercase-hyphenated.
- Copy the solve/exploit script alongside `index.md` if one exists and
  the writeup references it (matches convention, e.g.
  `writeups/2024/PatriotCTF/slingshot/solve.py`).
- Copy screenshots actually referenced by the writeup, alongside it.
- Copy the call-graph PNG from Step 3 if one was made, alongside
  `index.md` — but not the script that generated it.
- Do **not** copy the raw challenge binary/zip/flag.txt into the repo —
  none of the existing writeups do this for binary-heavy pwn/rev
  challenges; keep the repo lean. Flag this decision to the user only if
  a source folder's writeup can't stand on its own without the binary.

## Step 5 — Update navigation and CTF index

- `_data/navigation.yml`: find (or create) the `<year>` block, then the
  `<ctf-slug>` entry under it, and add a `- name: / link:` item for the
  new challenge under its `items:` list, matching the slug used in
  Step 4.
- `writeups/<year>/<ctf-slug>/index.md`: if it already exists, add the
  new challenge to whatever "solved" list/format it already uses. If it
  doesn't exist yet (new CTF), create a minimal one matching the pattern
  of other `<ctf>/index.md` files (title, dates if known, brief list of
  solved challenges) — check 1-2 existing ones for the exact shape first.
  Each solved-challenge list item must be a hyperlink to the writeup's
  live page, not bare text — e.g.
  `- [HRBot](https://shreethaar.github.io/ctf-writeups/writeups/<year>/<ctf-slug>/<challenge-slug>/) (pwn)`,
  matching the convention in `writeups/2025/neraca/index.md`.

## Step 6 — Commit

Stage exactly the files touched (writeup dir, `navigation.yml`, CTF
index.md) — never a broad `git add -A`. Commit with a short message
naming the CTF and challenge, e.g. `brunnerctf: add HRBot writeup`.
Follow the repo's existing commit message style (check `git log`) —
short, lowercase-ish, no body needed for a single writeup.

## Step 7 — Push (confirm first)

Show the user the commit (`git show --stat` or similar) and ask before
running `git push`. Never push without that explicit go-ahead in this
turn — a prior approval doesn't carry over to the next writeup.

## Notes for repeat use

This skill is meant to be re-run per challenge/per CTF. Each run should
independently re-check existing writeups for style rather than trusting
a cached impression from a previous run — the house style is defined by
whatever's actually in `writeups/`, which may evolve.

## Versioning

This skill is versioned, and mirrored into the writeups repo at
`.claude/skills/publish-writeup/SKILL.md`, so its history travels with
the site it publishes to. `.claude/` is a dot-directory, so Jekyll
ignores it and none of it is published.

After editing this skill:

1. Bump `version:` in the frontmatter — patch for wording, minor for a
   new rule or step, major for a reorganisation that changes how the
   skill is run.
2. Add an entry to `CHANGELOG.md` beside this file saying what changed
   and why.
3. Copy the edited file to the repo's `.claude/skills/publish-writeup/`
   and commit it together with the changelog, so the live skill at
   `~/.claude/skills/publish-writeup/` and the tracked copy never drift.
