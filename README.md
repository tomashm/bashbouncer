# BashBouncer

A shell command safety gate for Claude Code. Intercepts every Bash call before it runs.

For those who run `claude --dangerously-skip-permissions` but still want a safety net.

## How it works

```
command ──► prefix rules ──► LLM ──► ask you
                 │             │          │
            allow/deny     allow/deny  allow/deny
```

**Prefix rules** are checked first — zero latency. Sources:
- `Bash(prefix:*)` entries from Claude Code's settings files (all four: `<project>/.claude/settings.local.json`, `<project>/.claude/settings.json`, `~/.claude/settings.local.json`, `~/.claude/settings.json`)
- Allowlist/blocklist in `.claude/bashbouncer.local.md` frontmatter

Prefix matches are hard allow/deny — no LLM call, no user prompt.

**LLM classification** handles everything else — destructive git flags, secret variable references, file ops outside project root, cloud CLI mutations, system-wide installs. Uses Cerebras for fast, cheap inference.

**Ask you** is the fallback. If the LLM flags a command as unsafe or can't decide, you get four options: allow once, allow (teaches BashBouncer), block, or block always.

## What you'll see

**Nothing, most of the time.** Prefix-matched commands run silently. LLM-approved commands run with a subtle timing annotation.

When BashBouncer isn't sure, Claude asks you to allow or deny. If you allow, it offers to remember your choice so you're not asked again.

## Customizing rules

Create `.claude/bashbouncer.local.md` in your project root:

```markdown
---
allowlist:
  - docker
  - rails
  - bundle exec
  - terraform plan
blocklist:
  - terraform destroy
  - kubectl delete namespace
---

## Additional context

ssh to *.staging.example.com is safe.
Rails console is a normal part of our workflow.
```

**Allowlist/blocklist** entries are prefix-matched. `docker` matches `docker ps`, `docker compose up`, etc. `terraform plan` matches `terraform plan -out=foo` but not `terraform apply`.

**The markdown body** (after the `---`) gives the LLM extra context for classification. Write project-specific knowledge that prefix rules can't capture.

Blocklist wins over allowlist.

## Installation

BashBouncer uses [Cerebras](https://cloud.cerebras.ai/) for LLM classification (free API keys, generous limits):

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
