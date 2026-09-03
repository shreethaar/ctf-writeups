# Changelog — publish-writeup

The live skill lives at `~/.claude/skills/publish-writeup/`; this
directory is the tracked mirror. Versions are semver-ish: patch for
wording, minor for a new rule or step, major for a reorganisation that
changes how the skill is run.

## 1.1.0 — 2026-09-04

- Added **Step 3 — Add a call graph (rev / pwn challenges)**: when a
  graph earns its place and when to skip it; the call-graph vs
  control-flow-graph distinction and which one a writeup actually
  wants; Graphviz as the prerequisite, with the check and the
  ask-the-user-to-install rule; generating it via radare2 (`agCd` for
  the call graph, `agfd` for a single function's CFG) or from
  `kuna decompile-all --json` when the labels need to match the
  analysis; cross-checking function counts, because `r2 -A` only
  discovers functions something references and silently omits the rest;
  curation rules for readability (drop libc, label edges with the
  condition that takes them, number and colour the success path);
  and placement/format rules — PNG beside `index.md`, no generator
  script committed.
- Renumbered the old Steps 3-6 to 4-7 and fixed their cross-references.
- Step 4 (Place files): copy the call-graph PNG, not its generator.
- Frontmatter description now mentions the call graph.
- Added this changelog and the Versioning section.

## 1.0.0 — first numbered version

The skill as it stood at commit `fbf0cb5`, tracked in this repo since
`4fad76a` but unversioned until now: inputs to gather, reading every
raw source, rewriting in house style (including the Jekyll/Liquid
build-break rule and the not-solved-live framing), placing files,
updating navigation and the CTF index, committing, and confirming
before push.
