# Review format

The report contract for the automated reviewers (`Claude Code Review` and `opencode`). Both
workflows point at this file rather than restating the format, so a review reads the same
whichever reviewer produced it. What to review lives in
[`CLAUDE.md`](../CLAUDE.md); this file only covers how to report it.

## Step 1 — the iteration check

Before reviewing, read the existing comments on the PR:

```sh
gh pr view <number> --comments
```

**If there are previous reviews** (from either reviewer, from Copilot, or from a human):

- List every issue raised earlier and classify it: ✅ resolved · ❌ open · 🔄 partly resolved.
- Check each one against the **current** code, not against the reply in the thread. An issue
  acknowledged in a comment but never fixed is still open, and saying so is the single most
  useful thing a repeat review does.
- Do **not** restate open issues as new findings — reference them in the table instead.
- Raise the bar: later iterations are stricter than the first.

**If this is the first review**, say so in the iteration line and go straight to the analysis.

## Step 2 — the report

````markdown
## PR Review: [title] (#number)

**Decision**: 🔴 Blocked | 🟡 Minor changes | 🟢 Approved
**Iteration**: First review | Review #N (X resolved, Y open)
**Lenses applied**: [e.g. Rust under crates/, design decision (docs/adr/0031), CI]

### Executive summary

[Two or three sentences: what the PR does, overall assessment, where the risk is.]

### Previous issues

| # | Issue | Status | Notes |
|---|-------|--------|-------|
| 1 | [description] | ✅/❌/🔄 | [commit or comment reference] |

### New findings

#### 🔴 Blocking (resolve before merge)

**[file:line]** — category (confidence: 90-100)
> **Problem**: [what is wrong and why it matters]
> ```rust
> // current code
> ```
> **Fix**:
> ```rust
> // corrected code
> ```
> **Anchor**: [CLAUDE.md rule, threat-model section, ADR or RFC]

#### 🟡 Important (should be resolved)

**[file:line]** — category (confidence: 80-89)
> **Problem**: [description]
> **Fix**: [suggestion]
> **Anchor**: [rule]

#### 💡 Suggestions (nice to have)

- [file:line]: [one line]
````

Drop any section that has no content — an empty *Previous issues* table is noise. If nothing
reaches the threshold, say so explicitly and close with `**Decision**: 🟢 Approved`.

## Step 3 — severity and confidence

Score every finding 0-100 and report only **≥ 80**.

| Score | Meaning | Section |
|---|---|---|
| 90-100 | Confirmed bug, vulnerability, exposed secret, violated hard constraint | 🔴 Blocking |
| 80-89 | Real issue affecting behaviour, or breaking a stated rule | 🟡 Important |
| 51-79 | Valid but low impact | 💡 Suggestion, or omit |
| ≤ 50 | Nitpick, or a convention this repo never adopted | Do not report |

A hard constraint from `CLAUDE.md` — anything phrased as *never*, *forbid* or *reject* — is
blocking on its own, without arguing impact.

## Rules

- **Anchor every finding** to a `CLAUDE.md` rule, a threat-model section, or an ADR/RFC. A finding
  without an anchor is an opinion; drop it.
- **One comment per issue.** No duplicates.
- **Cite `file:line`**, always, with the concrete code.
- When linking to code, use the full commit SHA and a range with context —
  `https://github.com/<owner>/<repo>/blob/<full-sha>/<path>#L4-L7`. An abbreviated SHA or
  `$(git rev-parse HEAD)` will not render: the comment is Markdown, it is not executed.
- Commit suggestions only when committing them fixes the issue completely.
- Both Spanish and English are first-class here; match the language of the PR description.
