# Working on tokmap

## Commit messages

- Subject: imperative, at most 72 characters, no trailing period. Then a blank line.
- Body: what changed and why, as plain facts. Wrap at 72 characters.
- Say what was tested and how. If something is only unit-tested, or not tested, say so.
- No comparisons with other tools, and do not name other scanners.
- No performance or accuracy claims, no benchmark numbers, no words like "faster", "better",
  "beats" or "outperforms". Benchmark results belong in reports, not in history.
- No legal or licensing opinions.
- No secrets, tokens, email addresses, real hostnames or IP addresses, or personal paths.
- No tool attribution lines unless asked for.
- One logical change per commit. Never commit evidence, drafts, downloaded data files or
  scratch scripts.
- Never push to main, and never rewrite history that is already pushed.

`.githooks/commit-msg` checks the mechanical rules. Enable it once per clone:

```
git config core.hooksPath .githooks
```
