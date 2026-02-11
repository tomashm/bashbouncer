# BashBouncer

For those who run `claude --dangerously-skip-permissions` but still want a safety net.

A shell command classifier for Claude Code that intercepts every Bash call before it runs.

Every time Claude tries to execute a shell command, BashBouncer intercepts it and decides: allow silently, block with an explanation, or ask you.

## How it works

```
command ──► static rules ──► LLM (optional) ──► ask you
              │                    │                │
            allow/block      allow/block         allow/block
```

**Static rules** handle the obvious cases instantly — `ls`, `git status`, `grep` run without interruption. `sudo`, `rm -rf`, `echo $API_KEY` get blocked.

**LLM classification** (optional) catches the nuanced stuff that regex can't — destructive git flags, cloud CLI mutations, system-wide installs. Uses Cerebras for fast, cheap inference.

**Ask you** is the fallback. If neither tier is confident, you decide.

## Install

```
claude plugins install bashbouncer
```

That's it. No config needed. BashBouncer starts intercepting commands immediately.

## What you'll see

**Nothing, most of the time.** Safe commands run silently.

When something gets blocked:
```
BashBouncer [static] blocked: rm -rf node_modules -- 'rm -rf' is never allowed, use 'mv <target> /tmp/' instead
```

When BashBouncer isn't sure, Claude Code asks you to allow or deny. If you allow, Claude will offer to remember your choice so you're not asked again.

## Adding the LLM tier

Without an API key, commands that static rules can't classify go straight to "ask you." If you're getting asked too often, add a Cerebras key:

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
export CEREBRAS_API_KEY=your-key-here
```

Cerebras offers [free API keys](https://cloud.cerebras.ai/) with usage and rate limits — plenty for command classification.

## Customizing rules

Create `~/.claude/bashbouncer.local.md` to add your own rules:

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

**The markdown body** (after the `---`) gives the LLM extra context for classification. Use it for project-specific knowledge that static rules can't capture.

Rules stack: blocklist wins over allowlist. Neither overrides built-in blocks (`sudo`, `rm -rf`, etc. are always blocked).

## What gets blocked

**Always blocked:**
- `sudo`, `su`, `shutdown`, `reboot`, system administration commands
- `rm -rf` (any target)
- `env`, `printenv` without arguments (dumps secrets)
- References to secret variables (`$API_KEY`, `$DB_PASSWORD`, `${AUTH_TOKEN}`, etc.)
- `/proc/*/environ` access
- File operations outside your project directory

**Blocked by LLM** (when key is set):
- `git push --force`, `git reset --hard`, `git clean -f`
- `docker --privileged`, mounting host root
- Cloud CLI mutations (`aws s3 rm`, `terraform destroy`, `gcloud delete`)
- `curl` posting local files to external hosts
- System-wide package installs (`apt install`, `brew install`)

**Always allowed:**
- Read-only commands: `ls`, `cat`, `grep`, `find`, `diff`, `ps`, `top`
- Output commands: `echo`, `printf`, `date`, `whoami`
- File inspection: `wc`, `file`, `stat`, `md5sum`

## How Claude learns your preferences

When BashBouncer asks you about an unknown command and you allow it, Claude will offer:

> "Want me to add `docker` to your BashBouncer allowlist so you're not asked again?"

If you say yes, Claude edits `~/.claude/bashbouncer.local.md` for you. Over time, the "ask" prompts decrease as BashBouncer learns your workflow.
