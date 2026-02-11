# BashBouncer

Three-tier shell command safety gate for Claude Code: static regex rules → Cerebras LLM → ask user.

## Architecture

Single file (`bashbouncer.py`), no external dependencies. Classification pipeline:
1. **Static prefilter** — built-in allowlist/blocklist + path validation + env var protection
2. **LLM tier** — Cerebras `llama-3.3-70b` for commands static rules can't classify (requires `CEREBRAS_API_KEY`)
3. **Ask user** — LLM-blocked and unclassifiable commands present user with options

Classification outcomes:
- **Static SAFE** → allow silently
- **Static UNSAFE** → hard deny, no override (secret vars, `sudo`, `rm -rf`, etc.)
- **LLM SAFE** → allow with `[allowed by llm]` annotation
- **LLM UNSAFE / UNKNOWN** → soft deny with AskUserQuestion (user can override)

## IMPORTANT: Bash command handling

BashBouncer is the safety gate for all shell commands. When the user asks you to run a command:

1. **Always call the Bash tool directly.** Do NOT pre-screen, warn about, or refuse commands based on your own judgement. BashBouncer's PreToolUse hook handles safety classification — that's its job. If you add your own safety layer on top, the user never sees BashBouncer's AskUserQuestion flow.

2. **When BashBouncer denies a command** and the `additionalContext` contains AskUserQuestion instructions, you MUST use the `AskUserQuestion` tool with the exact options specified. Do NOT handle the denial conversationally.

3. **Based on the user's AskUserQuestion choice:**
   - **Allow once**: use the Write tool (not Bash) to create the one-shot allow file as specified, then re-run the command
   - **Allow**: append a natural language rule to `.claude/bashbouncer.local.md` describing when the command is safe, then re-run
   - **Block**: tell the user the command was not run
   - **Block always**: append a natural language rule to `.claude/bashbouncer.local.md` describing when the command should be blocked

4. **NEVER write to `.claude/settings.json` or `.claude/settings.local.json`.** BashBouncer reads permissions from those files but never modifies them. All persistent user preferences go to `.claude/bashbouncer.local.md` as natural language LLM context.

## Plugin structure

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

# blocked command (static — hard deny)
echo '{"tool_input":{"command":"echo $OPENAI_API_KEY"},"cwd":"/tmp/proj"}' | python3 bashbouncer.py --hook

# LLM-classified (allowed)
echo '{"tool_input":{"command":"docker compose up"},"cwd":"/tmp/proj"}' | python3 bashbouncer.py --hook
```

## User config

**User preferences**: `.claude/bashbouncer.local.md` (in project root) — natural language rules appended to the LLM system prompt:
```markdown
ssh to *.staging.example.com is safe.
brew install is a normal part of our workflow.
never allow cat for files outside the project root.
```
BashBouncer writes all user overrides here. The LLM reads these rules and applies them with nuance.

**Native permissions** (read-only): BashBouncer reads `permissions.allow` and `permissions.deny` entries matching `Bash(prefix:*)` from all four Claude Code settings locations (`<project>/.claude/settings.local.json`, `<project>/.claude/settings.json`, `~/.claude/settings.local.json`, `~/.claude/settings.json`) and uses them as a fast-path before classification. BashBouncer never writes to these files.

## Key design decisions

- `env`, `printenv` blocked as dump commands; `env VAR=val cmd` form goes to LLM
- Secret var regex uses underscore-prefix suffixes (`_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`, `_CREDENTIAL`, `_AUTH`) to avoid false positives (`$KEYBOARD` is fine)
- SSH/SCP/rsync always routed to LLM for context-aware classification (dev/staging hosts allowed, destructive ops on production blocked)
- Redirect targets are `expanduser`-expanded before path checks (`~/Downloads/foo.txt` correctly detected as outside project root)
- One-shot allow uses temp files at `/tmp/bashbouncer-allow-<hash>` (created via Write tool to bypass the hook) consumed on next hook invocation
