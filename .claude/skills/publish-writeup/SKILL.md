---
name: publish-writeup
description: |
  Converts raw CTF challenge notes (draft writeups, README hints, solve
  scripts, screenshots) from an arbitrary source folder into this repo's
  house writeup style, places them at writeups/<year>/<ctf>/<challenge>/,
  updates _data/navigation.yml and the CTF's index.md, commits locally,
  and asks for confirmation before pushing. Use whenever the user has
  solved a CTF challenge and wants their raw notes turned into a published
  writeup on shreethaar.github.io/ctf-writeups.
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

## Step 3 — Place files

- Writeup: `writeups/<year>/<ctf-slug>/<challenge-slug>/index.md`
  (create parent dirs as needed). Match the challenge-slug casing style
  already used for that CTF's other challenges in `navigation.yml` if
  any exist, otherwise lowercase-hyphenated.
- Copy the solve/exploit script alongside `index.md` if one exists and
  the writeup references it (matches convention, e.g.
  `writeups/2024/PatriotCTF/slingshot/solve.py`).
- Copy screenshots actually referenced by the writeup, alongside it.
- Do **not** copy the raw challenge binary/zip/flag.txt into the repo —
  none of the existing writeups do this for binary-heavy pwn/rev
  challenges; keep the repo lean. Flag this decision to the user only if
  a source folder's writeup can't stand on its own without the binary.

## Step 4 — Update navigation and CTF index

- `_data/navigation.yml`: find (or create) the `<year>` block, then the
  `<ctf-slug>` entry under it, and add a `- name: / link:` item for the
  new challenge under its `items:` list, matching the slug used in
  Step 3.
- `writeups/<year>/<ctf-slug>/index.md`: if it already exists, add the
  new challenge to whatever "solved" list/format it already uses. If it
  doesn't exist yet (new CTF), create a minimal one matching the pattern
  of other `<ctf>/index.md` files (title, dates if known, brief list of
  solved challenges) — check 1-2 existing ones for the exact shape first.
  Each solved-challenge list item must be a hyperlink to the writeup's
  live page, not bare text — e.g.
  `- [HRBot](https://shreethaar.github.io/ctf-writeups/writeups/<year>/<ctf-slug>/<challenge-slug>/) (pwn)`,
  matching the convention in `writeups/2025/neraca/index.md`.

## Step 5 — Commit

Stage exactly the files touched (writeup dir, `navigation.yml`, CTF
index.md) — never a broad `git add -A`. Commit with a short message
naming the CTF and challenge, e.g. `brunnerctf: add HRBot writeup`.
Follow the repo's existing commit message style (check `git log`) —
short, lowercase-ish, no body needed for a single writeup.

## Step 6 — Push (confirm first)

Show the user the commit (`git show --stat` or similar) and ask before
running `git push`. Never push without that explicit go-ahead in this
turn — a prior approval doesn't carry over to the next writeup.

## Notes for repeat use

This skill is meant to be re-run per challenge/per CTF. Each run should
independently re-check existing writeups for style rather than trusting
a cached impression from a previous run — the house style is defined by
whatever's actually in `writeups/`, which may evolve.
