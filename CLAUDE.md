# BashBouncer

Three-tier shell command safety gate for Claude Code: static regex rules → Cerebras LLM → ask user.

## Architecture

Single file (`bashbouncer.py`), no external dependencies. Classification pipeline:
1. **Static prefilter** — allowlist/blocklist + path validation + env var protection
2. **LLM tier** — Cerebras `llama-3.3-70b` for commands static rules can't classify (requires `CEREBRAS_API_KEY`)
3. **Ask user** — falls through to Claude Code's permission prompt

Plugin structure:
```
.claude-plugin/plugin.json    # plugin manifest
hooks/hooks.json              # PreToolUse hook config
bashbouncer.py                # classifier (all logic here)
```


## Running

```bash
./bashbouncer.py commands.jsonl  # directly
uv run bashbouncer.py commands.jsonl  # or with uv

# hook mode (reads Claude Code hook JSON from stdin)
./bashbouncer.py --hook
```

## Testing hook mode

```bash
# safe command
echo '{"tool_input":{"command":"ls -la"},"cwd":"/tmp/proj"}' | python3 bashbouncer.py --hook

# blocked command
echo '{"tool_input":{"command":"echo $OPENAI_API_KEY"},"cwd":"/tmp/proj"}' | python3 bashbouncer.py --hook

# unknown → ask (or LLM if CEREBRAS_API_KEY is set)
echo '{"tool_input":{"command":"docker compose up"},"cwd":"/tmp/proj"}' | python3 bashbouncer.py --hook
```

## User config

`~/.claude/bashbouncer.local.md` — created by user (or by Claude when user approves a command). Format:

```markdown
---
allowlist:
  - docker
  - rails
  - bundle exec
blocklist:
  - terraform destroy
  - kubectl delete namespace
---

## Additional classification context

ssh to *.staging.example.com is safe.
Rails console is a normal part of our workflow.
```

- YAML frontmatter: `allowlist` and `blocklist` entries are prefix-matched against commands
- Markdown body: appended to the LLM system prompt for tier-2 classification
- Blocklist wins over allowlist if both match
- Neither overrides built-in UNSAFE_ALWAYS (e.g. `sudo` can't be allowlisted)

## Key design decisions

- `env`, `printenv` blocked as dump commands; `env VAR=val cmd` form goes to LLM
- Secret var regex uses underscore-prefix suffixes (`_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`, `_CREDENTIAL`, `_AUTH`) to avoid false positives (`$KEYBOARD` is fine)
- Hook systemMessage hints tell Claude to offer updating `~/.claude/bashbouncer.local.md` when user approves/denies unknown commands
