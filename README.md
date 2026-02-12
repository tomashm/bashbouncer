# BashBouncer

A shell command safety gate for Claude Code that learns as you use it. Intercepts every Bash call before it runs. Powered by Llama on [Cerebras](https://cerebras.ai/) — lightning fast inference.

For those who run `claude --dangerously-skip-permissions` but still want a safety net.

## Example session
```
❯ claude --dangerously-skip-permissions

 ▐▛███▜▌   Claude Code v2.1.39
▝▜█████▛▘  Opus 4.6 · Claude API
  ▘▘ ▝▝    /Users/tomashm

❯ ssh to 192.168.1.1 and reboot it using "shutdown"

⏺ This will reboot a remote machine, which disrupts any running services and active connections. Before I proceed:

  - Is this a device you control (e.g., home router at 192.168.1.1)?
  - Are you fine with immediate reboot (shutdown -r now)?

  If so, I'll run:

  ssh 192.168.1.1 'sudo shutdown -r now'

  Confirm and I'll execute it.

❯ yes

⏺ Bash(ssh 192.168.1.1 'sudo shutdown -r now')
  ⎿  PreToolUse:Bash hook returned blocking error
  ⎿  Error: BashBouncer LLM flagged as unsafe

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ☐ ssh

`ssh 192.168.1.1 'sudo shutdown -r now'` was flagged by BashBouncer. How should it be handled?

❯ 1. Allow once
     Run this time only
  2. Allow
     Teach BashBouncer that ssh is safe
  3. Block
     Don't run it
  4. Block always
     Teach BashBouncer to always block this
  5. Type something.
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  6. Chat about this

Enter to select · ↑/↓ to navigate · Esc to cancel
```

## How it works

```
command ──► prefix rules ──► LLM ──► ask you
                 │             │          │
            allow/deny     allow/deny  allow/deny
```

**Prefix rules** are checked first — zero latency. Reads `Bash(prefix:*)` entries from Claude Code's settings files (all four: `<project>/.claude/settings.local.json`, `<project>/.claude/settings.json`, `~/.claude/settings.local.json`, `~/.claude/settings.json`). Prefix matches are hard allow/deny — no LLM call, no user prompt.

**LLM classification** handles everything else — destructive git flags, secret variable references, file ops outside project root, cloud CLI mutations, system-wide installs. Uses Cerebras for fast, cheap inference (3s timeout — falls back to allow if the API is slow). LLM memory is managed in `.claude/bashbouncer.local.md`.

**Ask you** is the fallback. If the LLM flags a command as unsafe or can't decide, you get four options: allow once, allow (teaches BashBouncer), block, or block always.

## What you'll see

**Nothing, most of the time.** Prefix-matched commands run silently. LLM-approved commands run with a subtle timing annotation.

When BashBouncer isn't sure, Claude asks you to allow or deny. If you allow, it offers to remember your choice so you're not asked again.

## Customizing rules

Create `.claude/bashbouncer.local.md` in your project root, or just let BashBouncer update this file for you as you allow/block commands:

```markdown
ssh to *.staging.example.com is safe.
Rails console is a normal part of our workflow.
Never allow terraform destroy.
```

This file is passed as additional context to the LLM classifier. Write project-specific knowledge in natural language — the LLM reads it and applies it with nuance.

## Installation

BashBouncer uses [Cerebras](https://cloud.cerebras.ai/) for LLM classification (lightning fast, free API keys, generous limits):

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
export CEREBRAS_API_KEY=your-key-here
```

Then install the plugin:

```bash
# Add marketplace
claude plugin marketplace add tomashm/bashbouncer

# Install plugin
claude plugin install bashbouncer@bashbouncer

# Update later
claude plugin update bashbouncer@bashbouncer
```

## License

MIT
