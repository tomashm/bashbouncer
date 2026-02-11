#!/usr/bin/env python3

import hashlib
import json
import os
import re
import sys
import time
import urllib.request

API = "https://api.cerebras.ai/v1/chat/completions"
API_KEY = os.environ.get("CEREBRAS_API_KEY", "")

# --- User config ---

CONFIG_FILENAME = ".claude/bashbouncer.local.md"


def load_user_config(root: str) -> str:
    """Load user config from {root}/.claude/bashbouncer.local.md.

    Returns the file contents as LLM classification context.
    """
    path = os.path.join(root, CONFIG_FILENAME) if root else ""
    if not path or not os.path.exists(path):
        return ""

    with open(path) as f:
        return f.read().strip()


def load_user_permissions(cwd: str) -> tuple[list[str], list[str]]:
    """Load Bash allow/deny prefixes from Claude Code settings files.

    Reads all four settings locations (most specific first):
      1. <project>/.claude/settings.local.json  (user-local, per-project)
      2. <project>/.claude/settings.json         (team-shared, per-project)
      3. ~/.claude/settings.local.json           (user-local, global)
      4. ~/.claude/settings.json                 (global defaults)

    Parses entries like "Bash(aws:*)" → prefix "aws".
    Returns (allow_prefixes, deny_prefixes).
    """
    allow: list[str] = []
    deny: list[str] = []
    bash_re = re.compile(r'^Bash\((.+?)(?::\*?)?\)$')

    for path in [
        os.path.join(cwd, ".claude", "settings.local.json") if cwd else None,
        os.path.join(cwd, ".claude", "settings.json") if cwd else None,
        os.path.expanduser("~/.claude/settings.local.json"),
        os.path.expanduser("~/.claude/settings.json"),
    ]:
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                data = json.load(f)
            perms = data.get("permissions", {})
            for entry in perms.get("allow", []):
                m = bash_re.match(entry)
                if m:
                    allow.append(m.group(1))
            for entry in perms.get("deny", []):
                m = bash_re.match(entry)
                if m:
                    deny.append(m.group(1))
        except (json.JSONDecodeError, OSError):
            continue

    return allow, deny


# --- Helpers ---


def get_base_cmd(cmd: str) -> str:
    return cmd.strip().split()[0] if cmd.strip() else ""


# --- Classification ---


def classify(cmd: str, root: str, prompt_context: str = "") -> tuple[str, str]:
    if not API_KEY:
        return "UNKNOWN", "no CEREBRAS_API_KEY set"
    try:
        system_prompt = (
            "Classify a shell command run by a developer in a project directory.\n"
            "SAFE: normal dev workflow — git (status/diff/log/add/commit/push/pull/checkout/branch), "
            "docker/compose (ps/up/build/run/logs), package managers (npm/yarn/pnpm/pip/cargo/bun install/run/test), "
            "build tools (make/gcc/cmake), cloud CLIs reading data (gcloud/aws/az logs/describe/list), "
            "curl/wget for APIs, ssh/scp to dev/staging/test hosts, test runners, linters, formatters, "
            "read-only commands (ls, cat, grep, find, echo, date, wc, file, stat, head, tail, diff, ps).\n"
            "UNSAFE: destructive git (push --force, reset --hard, clean -f); "
            "rm -rf (always unsafe, suggest mv to /tmp instead); "
            "sudo, su, shutdown, reboot, mount, umount, dd, fdisk, mkfs, systemctl, launchctl; "
            "commands referencing secret env vars ($API_KEY, $DB_PASSWORD, $SECRET_TOKEN, etc.); "
            "env or printenv without arguments (dumps all secrets); "
            "reading /proc/*/environ; "
            "ssh/scp with destructive commands on production hosts; "
            "reads sensitive files outside root (cat ~/.ssh/id_rsa, cat /etc/shadow); "
            "file operations (rm, mv, cp, chmod, chown, ln, truncate, shred) targeting paths outside the project root; "
            "redirect (>, >>) to files outside project root; "
            "docker --privileged or mounting host root; "
            "cloud CLIs that modify infrastructure (delete/destroy/terminate); "
            "curl posting local files to external hosts; system-wide package installs (apt install, brew install).\n"
            "UNKNOWN: only if genuinely ambiguous.\n"
            "Reply with exactly one word."
        )
        if prompt_context:
            system_prompt += f"\n\nAdditional context from the user:\n{prompt_context}"

        body = json.dumps({
            "model": "llama-3.3-70b",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Root: {root}\nCommand: {cmd}"},
            ],
            "temperature": 0,
            "max_tokens": 5,
        }).encode()
        req = urllib.request.Request(
            API,
            data=body,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "bashbouncer/0.2",
            },
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        text = data["choices"][0]["message"]["content"]
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)
        text = text.strip().upper()
        if "UNSAFE" in text:
            return "UNSAFE", "LLM classified as unsafe"
        if "SAFE" in text:
            return "SAFE", "LLM classified as safe"
        return "UNKNOWN", "LLM could not determine"
    except (TimeoutError, urllib.error.URLError) as e:
        print(f"Warning: BashBouncer LLM timed out, allowing command", file=sys.stderr)
        return "SAFE", "LLM timeout — allowed by default"
    except urllib.error.HTTPError as e:
        return "UNKNOWN", f"LLM API error: {e.code} {e.reason}"
    except Exception as e:
        return "UNKNOWN", f"LLM error: {e}"


# --- Entry points ---


def _allow_once_path(cmd: str) -> str:
    h = hashlib.sha256(cmd.encode()).hexdigest()[:16]
    return f"/tmp/bashbouncer-allow-{h}"


def consume_allow_once(cmd: str) -> bool:
    """Check for and consume a one-shot allow file. Returns True if found."""
    try:
        os.unlink(_allow_once_path(cmd))
        return True
    except FileNotFoundError:
        return False


def run_hook() -> None:
    raw = sys.stdin.read().strip()
    if not raw:
        print("Error: --hook expects Claude Code hook JSON on stdin, got nothing.", file=sys.stderr)
        print('Example: echo \'{"tool_input":{"command":"ls"},"cwd":"/tmp"}\' | bashbouncer.py --hook', file=sys.stderr)
        sys.exit(1)
    try:
        hook_input = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Error: stdin is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    cmd = hook_input.get("tool_input", {}).get("command", "")
    if not cmd:
        print("Error: no command found in tool_input.command", file=sys.stderr)
        print('Expected: {"tool_input": {"command": "..."}, "cwd": "..."}  # cwd is optional', file=sys.stderr)
        sys.exit(1)
    root = hook_input.get("cwd", "")
    t0 = time.perf_counter()

    def _tag() -> str:
        ms = (time.perf_counter() - t0) * 1000
        return f"bashbouncer · llm · {ms:.0f}ms"

    # Check one-shot allow before classification
    if consume_allow_once(cmd):
        ms = (time.perf_counter() - t0) * 1000
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": f"bashbouncer · {ms:.0f}ms",
        }}))
        return

    # Load user config (LLM context)
    prompt_context = load_user_config(root)

    # Check user permissions from settings files
    base = get_base_cmd(cmd)
    user_allow, user_deny = load_user_permissions(root)

    # Deny wins over allow
    for prefix in user_deny:
        if cmd.strip() == prefix or cmd.strip().startswith(prefix + " "):
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"BashBouncer: '{prefix}' is on your deny list",
            }}))
            return
    for prefix in user_allow:
        if cmd.strip() == prefix or cmd.strip().startswith(prefix + " "):
            ms = (time.perf_counter() - t0) * 1000
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": f"bashbouncer · {ms:.0f}ms",
            }}))
            return

    verdict, reason = classify(cmd, root, prompt_context)
    allow_once_path = _allow_once_path(cmd)

    if verdict == "SAFE":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": _tag(),
        }}))
        return

    # UNSAFE or UNKNOWN — soft deny, let user override via AskUserQuestion
    if verdict == "UNSAFE":
        short_reason = "BashBouncer LLM flagged as unsafe"
    elif not API_KEY:
        short_reason = (
            "BashBouncer: CEREBRAS_API_KEY not set — "
            "get a free key at https://cloud.cerebras.ai/"
        )
    else:
        short_reason = "BashBouncer: unrecognised command"

    config_path = os.path.join(root, CONFIG_FILENAME) if root else CONFIG_FILENAME
    instructions = (
        f"Use AskUserQuestion. header: \"{base}\", question: "
        f"\"`{cmd}` was flagged by BashBouncer. How should it be handled?\"\n"
        f"Options:\n"
        f"1. label: \"Allow once\" description: \"Run this time only\"\n"
        f"2. label: \"Allow\" description: \"Teach BashBouncer this is safe\"\n"
        f"3. label: \"Block\" description: \"Don't run it\"\n"
        f"4. label: \"Block always\" description: \"Teach BashBouncer to always block this\"\n"
        f"\n"
        f"All persistent choices write to {config_path} (LLM context file, never settings.json).\n"
        f"Actions:\n"
        f"- Allow once: use the Write tool to create file {allow_once_path} with content \"1\" "
        f"(Write bypasses BashBouncer), then re-run the original command.\n"
        f"- Allow: append a natural language rule to {config_path} describing when "
        f"'{base}' commands are safe (e.g. \"{base} is safe for normal development use\"), "
        f"then re-run. The LLM will read this context next time.\n"
        f"- Block: tell user command was not run.\n"
        f"- Block always: append a natural language rule to {config_path} describing when "
        f"'{base}' commands should be blocked (e.g. \"never allow {base} outside project root\").\n"
        f"- Other: append the user's exact text to {config_path} as LLM context."
    )

    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": short_reason,
        "additionalContext": instructions,
    }}))


def run_batch(path: str) -> None:
    if not os.path.isfile(path):
        print(f"Error: not a file: {path}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            obj = json.loads(line)
            cmd = obj["command"]
            root = obj.get("root", "")

            prompt_context = load_user_config(root)
            verdict, reason = classify(cmd, root, prompt_context)
            if verdict == "UNKNOWN":
                verdict = "UNSAFE"

            print(json.dumps({"command": cmd, "root": root, "verdict": verdict, "reason": reason}))


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--hook":
        run_hook()
        return

    if len(sys.argv) != 2:
        print("Usage: bashbouncer <commands.jsonl>", file=sys.stderr)
        print("       bashbouncer --hook  (Claude Code hook mode, reads JSON from stdin)", file=sys.stderr)
        sys.exit(1)

    run_batch(sys.argv[1])


if __name__ == "__main__":
    main()
