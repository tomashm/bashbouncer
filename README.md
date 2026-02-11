# BashBouncer

A shell command safety gate for Claude Code. Intercepts every Bash call before it runs.

For those who run `claude --dangerously-skip-permissions` but still want a safety net.

## How it works

```
command ──► static rules ──► LLM (optional) ──► ask you
              │                    │                │
            allow/block      allow/block         allow/block
```

**Static rules** handle the obvious cases instantly — `ls`, `git status`, `grep` run without interruption. `sudo`, `rm -rf`, `echo $API_KEY` get blocked.

**LLM classification** (optional) catches the nuanced stuff that regex can't — destructive git flags, cloud CLI mutations, system-wide installs. Uses Cerebras for fast, cheap inference.

**Ask you** is the fallback. If neither tier is confident, you decide.

## What gets blocked

| Category | Examples |
|----------|----------|
| **Always blocked** | `sudo`, `rm -rf`, `env`/`printenv` (dumps secrets), `$API_KEY`/`$DB_PASSWORD`, `/proc/*/environ`, file ops outside project root |
| **Blocked by LLM** | `git push --force`, `docker --privileged`, `aws s3 rm`, `terraform destroy`, `curl` posting local files, system-wide installs |
| **Always allowed** | `ls`, `cat`, `grep`, `find`, `echo`, `date`, `wc`, `file`, `stat` |

## What you'll see

**Nothing, most of the time.** Safe commands run silently.

When something gets blocked:
```
BashBouncer [static] blocked: rm -rf node_modules -- 'rm -rf' is never allowed, use 'mv <target> /tmp/' instead
```

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

**The markdown body** (after the `---`) gives the LLM extra context for classification. Write project-specific knowledge that static rules can't capture.

Blocklist wins over allowlist. Neither overrides built-in blocks (`sudo`, `rm -rf`, etc. are always blocked).

## Adding the LLM tier

Without an API key, commands that static rules can't classify go straight to "ask you." Add a Cerebras key to reduce prompts:

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
export CEREBRAS_API_KEY=your-key-here
```

Cerebras offers [free API keys](https://cloud.cerebras.ai/) with generous limits — plenty for command classification.

## Installation

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
