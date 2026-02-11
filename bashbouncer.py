#!/usr/bin/env python3

import hashlib
import json
import os
import re
import shlex
import sys
import urllib.request

API = "https://api.cerebras.ai/v1/chat/completions"
API_KEY = os.environ.get("CEREBRAS_API_KEY", "")

# --- Built-in command lists ---

SAFE_CMDS = set(
    "echo printf date whoami pwd uname hostname uptime id groups "
    "df du wc file which where type stat head tail cat less more ls dir find fd "
    "rg grep egrep fgrep diff cmp comm ps top htop pgrep lsof free vmstat iostat "
    "w who last finger man whatis apropos help true false test sort uniq tr cut "
    "awk sed seq basename dirname realpath readlink tput column fmt nl od xxd "
    "hexdump strings md5sum sha256sum sha1sum cksum b2sum nproc arch getconf".split()
)

UNSAFE_ALWAYS = set(
    "sudo su shutdown reboot halt poweroff "
    "mount umount fdisk parted mkfs dd "
    "useradd userdel usermod groupadd crontab at "
    "systemctl service launchctl defaults dscl".split()
)

FILE_OPS = frozenset(
    "rm rmdir mv cp chmod chown chgrp ln unlink truncate shred tee touch mkdir".split()
)

READ_CMDS = frozenset(
    "cat head tail less more strings xxd hexdump od".split()
)

ENV_DUMP_CMDS = frozenset(("env", "printenv"))

# Matches $VAR or ${VAR} where VAR contains secret-like suffixes
SECRET_VAR_RE = re.compile(
    r"\$\{?[A-Z_]*(API_KEY|_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL|_AUTH)\}?"
)

PROC_ENVIRON_RE = re.compile(r"/proc/(\d+|self)/environ")

# --- User config ---

CONFIG_FILENAME = ".claude/bashbouncer.local.md"


def load_user_config(root: str) -> tuple[list[str], list[str], str]:
    """Load user config from {root}/.claude/bashbouncer.local.md.

    Returns (allowlist, blocklist, prompt_context).
    Frontmatter allowlist/blocklist entries are prefix-matched against commands.
    Markdown body is passed as additional LLM classification context.
    """
    path = os.path.join(root, CONFIG_FILENAME) if root else ""
    if not path or not os.path.exists(path):
        return [], [], ""

    with open(path) as f:
        text = f.read()

    if not text.startswith("---"):
        return [], [], text.strip()

    parts = text.split("---", 2)
    prompt_context = parts[2].strip() if len(parts) > 2 else ""

    # Parse simple YAML list format (no PyYAML dependency):
    #   allowlist:
    #     - docker
    #     - rails
    allowlist: list[str] = []
    blocklist: list[str] = []
    current_key: list[str] | None = None
    for line in parts[1].splitlines():
        stripped = line.strip()
        if stripped == "allowlist:":
            current_key = allowlist
        elif stripped == "blocklist:":
            current_key = blocklist
        elif stripped.startswith("- ") and current_key is not None:
            current_key.append(stripped[2:].strip())
        elif stripped and not stripped.startswith("#"):
            current_key = None

    return allowlist, blocklist, prompt_context


def load_user_permissions(cwd: str) -> tuple[list[str], list[str]]:
    """Load Bash allow/deny prefixes from .claude/settings.local.json.

    Parses entries like "Bash(aws:*)" → prefix "aws".
    Returns (allow_prefixes, deny_prefixes).
    """
    allow: list[str] = []
    deny: list[str] = []
    bash_re = re.compile(r'^Bash\((.+?)(?::\*?)?\)$')

    for path in [
        os.path.join(cwd, ".claude", "settings.local.json") if cwd else None,
        os.path.expanduser("~/.claude/settings.local.json"),
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


def is_within_root(path: str, root: str) -> bool:
    root = os.path.normpath(root)
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.join(root, path)
    path = os.path.normpath(path)
    return path == root or path.startswith(root + os.sep)


def check_paths_in_root(segment: str, root: str) -> bool:
    try:
        parts = shlex.split(segment)
    except ValueError:
        return False
    if not parts:
        return False
    args = [a for a in parts[1:] if not a.startswith("-")]
    if not args:
        return False
    return all(is_within_root(a, root) for a in args)


def get_base_cmd(segment: str) -> str:
    return segment.strip().split()[0] if segment.strip() else ""


def has_dotpath(path: str) -> bool:
    return any(p.startswith(".") and p not in (".", "..") for p in os.path.normpath(path).split(os.sep))


def check_dotpath_args(segment: str, root: str) -> str | None:
    try:
        parts = shlex.split(segment)
    except ValueError:
        return None
    for arg in parts[1:]:
        if arg.startswith("-"):
            continue
        expanded = os.path.expanduser(arg)
        if not os.path.isabs(expanded) and root:
            expanded = os.path.join(root, expanded)
        expanded = os.path.normpath(expanded)
        if has_dotpath(expanded) and (not root or not is_within_root(expanded, root)):
            return arg
    return None


def check_reads_outside_root(segment: str, root: str) -> str | None:
    try:
        parts = shlex.split(segment)
    except ValueError:
        return None
    for arg in parts[1:]:
        if arg.startswith("-"):
            continue
        expanded = os.path.expanduser(arg)
        if not os.path.isabs(expanded):
            continue
        if not is_within_root(expanded, root):
            return arg
    return None


def has_non_flag_args(segment: str) -> bool:
    """Check if segment has non-flag arguments after the command."""
    try:
        parts = shlex.split(segment)
    except ValueError:
        return False
    return any(not a.startswith("-") for a in parts[1:])


# --- Classification ---


def prefilter(cmd: str, root: str) -> tuple[str, str]:
    # Secret variable references — check before subshell detection
    if SECRET_VAR_RE.search(cmd):
        return "UNSAFE", "references secret environment variable"

    # /proc/*/environ access
    if PROC_ENVIRON_RE.search(cmd):
        return "UNSAFE", "reads process environment file"

    # Subshells / command substitution -> UNKNOWN
    if re.search(r"\$\(|`|<\(|>\(", cmd):
        return "UNKNOWN", "contains subshell or command substitution"

    # Redirects: check target against root
    # Match >, >>, 2>, 2>> etc. Exclude trailing ; & | from target.
    for redir in re.finditer(r"\d?>>?\s*([^\s;&|]+)", cmd):
        target = os.path.expanduser(redir.group(1))
        if target == "/dev/null":
            continue
        if root and is_within_root(target, root):
            continue
        return "UNSAFE", f"redirect target '{target}' outside project root"

    # Split on pipes / chains
    segments = re.split(r"[|;&]{1,2}", cmd)

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        base = get_base_cmd(seg)

        if base in UNSAFE_ALWAYS:
            return "UNSAFE", f"'{base}' is on the block list"

        if base == "rm":
            short_flags = set()
            has_recursive = False
            for a in seg.split()[1:]:
                if a == "--recursive":
                    has_recursive = True
                elif a.startswith("-") and not a.startswith("--"):
                    short_flags.update(a[1:])
            if ("r" in short_flags or has_recursive) and "f" in short_flags:
                return "UNSAFE", "'rm -rf' is never allowed, use 'mv <target> /tmp/' instead"

        # Env dump commands
        if base in ENV_DUMP_CMDS:
            if not has_non_flag_args(seg):
                return "UNSAFE", f"'{base}' dumps environment variables including secrets"
            return "UNKNOWN", f"'{base}' may dump environment variables"

        # SSH/SCP/rsync: always route through LLM for context-aware classification
        if base in ("ssh", "scp", "rsync"):
            return "UNKNOWN", f"'{base}' runs commands on remote hosts"

        if base in FILE_OPS:
            if not root or not check_paths_in_root(seg, root):
                return "UNSAFE", f"'{base}' writes outside project root"
            continue

        if base not in SAFE_CMDS:
            return "UNKNOWN", f"'{base}' not in allow/block lists"

        dotarg = check_dotpath_args(seg, root)
        if dotarg is not None:
            return "UNKNOWN", f"accesses dotpath '{dotarg}' outside project root"

        if base in READ_CMDS and root:
            outside = check_reads_outside_root(seg, root)
            if outside is not None:
                return "UNKNOWN", f"reads '{outside}' outside project root"

    return "SAFE", "all commands on the allow list"


def classify_llm(cmd: str, root: str, prompt_context: str = "") -> tuple[str, str]:
    if not API_KEY:
        return "UNKNOWN", "no CEREBRAS_API_KEY set"
    try:
        system_prompt = (
            "Classify a shell command run by a developer in a project directory.\n"
            "SAFE: normal dev workflow — git (status/diff/log/add/commit/push/pull/checkout/branch), "
            "docker/compose (ps/up/build/run/logs), package managers (npm/yarn/pnpm/pip/cargo/bun install/run/test), "
            "build tools (make/gcc/cmake), cloud CLIs reading data (gcloud/aws/az logs/describe/list), "
            "curl/wget for APIs, ssh/scp to dev/staging/test hosts, test runners, linters, formatters.\n"
            "UNSAFE: destructive git (push --force, reset --hard, clean -f); "
            "ssh/scp with destructive commands on production hosts; "
            "reads sensitive files outside root (cat ~/.ssh/id_rsa, cat /etc/shadow); "
            "commands that dump or exfiltrate environment variables (env, printenv, echo $SECRET_KEY); "
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
        with urllib.request.urlopen(req, timeout=10) as resp:
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
    except urllib.error.HTTPError as e:
        return "UNKNOWN", f"LLM API error: {e.code} {e.reason}"
    except Exception as e:
        return "UNKNOWN", f"LLM error: {e}"


def classify(cmd: str, root: str, prompt_context: str = "") -> tuple[str, str, str]:
    verdict, reason = prefilter(cmd, root)
    if verdict == "UNKNOWN":
        verdict, reason = classify_llm(cmd, root, prompt_context)
        return verdict, "llm", reason
    return verdict, "static", reason


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

    # Check one-shot allow before classification
    if consume_allow_once(cmd):
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }}))
        return

    # Load user config (frontmatter allowlist/blocklist + LLM context)
    config_allow, config_block, prompt_context = load_user_config(root)

    # Check user permissions from settings.local.json + frontmatter
    base = get_base_cmd(cmd)
    user_allow, user_deny = load_user_permissions(root)
    user_deny.extend(config_block)
    user_allow.extend(config_allow)

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
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }}))
            return
    verdict, source, reason = classify(cmd, root, prompt_context)
    allow_once_path = _allow_once_path(cmd)

    if verdict == "SAFE":
        output: dict = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }}
        if source == "llm":
            output["hookSpecificOutput"]["permissionDecisionReason"] = (
                f"[allowed by {source}]"
            )
        print(json.dumps(output))
        return

    # Static UNSAFE — hard deny, no override
    if verdict == "UNSAFE" and source == "static":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"BashBouncer [{source}] blocked: {cmd} -- {reason}"
            ),
        }}))
        return

    # LLM UNSAFE or UNKNOWN — soft deny, let user override via AskUserQuestion
    if verdict == "UNSAFE":
        short_reason = f"BashBouncer LLM flagged as unsafe"
    else:
        short_reason = f"BashBouncer: unrecognised command"

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

    regex_calls = 0
    llm_calls = 0

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            obj = json.loads(line)
            cmd = obj["command"]
            root = obj.get("root", "")

            _, _, prompt_context = load_user_config(root)
            verdict, source, reason = classify(cmd, root, prompt_context)
            if source == "llm":
                if verdict == "UNKNOWN":
                    verdict = "UNSAFE"
                llm_calls += 1
            else:
                regex_calls += 1

            print(json.dumps({"command": cmd, "root": root, "verdict": verdict, "source": source, "reason": reason}))

    print(f"--- stats: regex={regex_calls}  llm={llm_calls} ---", file=sys.stderr)


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
