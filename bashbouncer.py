#!/usr/bin/env python3

import json
import os
import re
import shlex
import sys
import urllib.request

API = "https://api.cerebras.ai/v1/chat/completions"
API_KEY = os.environ.get("CEREBRAS_API_KEY", "")

SAFE_CMDS = frozenset(
    "echo printf date whoami pwd uname hostname uptime id groups env printenv "
    "df du wc file which where type stat head tail cat less more ls dir find fd "
    "rg grep egrep fgrep diff cmp comm ps top htop pgrep lsof free vmstat iostat "
    "w who last finger man whatis apropos help true false test sort uniq tr cut "
    "awk sed seq basename dirname realpath readlink tput column fmt nl od xxd "
    "hexdump strings md5sum sha256sum sha1sum cksum b2sum nproc arch getconf".split()
)

UNSAFE_ALWAYS = frozenset(
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


def is_within_root(path: str, root: str) -> bool:
    root = os.path.normpath(root)
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


def prefilter(cmd: str, root: str) -> tuple[str, str]:
    # Subshells / command substitution -> UNKNOWN
    if re.search(r"\$\(|`|<\(|>\(", cmd):
        return "UNKNOWN", "contains subshell or command substitution"

    # Redirects: check target against root
    redir = re.search(r">>?\s*(\S+)", cmd)
    if redir:
        target = redir.group(1)
        if root and is_within_root(target, root):
            return "SAFE", "redirect target within project root"
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
            flags = [c for a in seg.split()[1:] if a.startswith("-") for c in a.lstrip("-")]
            if "r" in flags and "f" in flags:
                return "UNSAFE", "'rm -rf' is never allowed, use 'mv <target> /tmp/' instead"

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


def classify_llm(cmd: str, root: str) -> tuple[str, str]:
    if not API_KEY:
        return "UNKNOWN", "no CEREBRAS_API_KEY set"
    try:
        body = json.dumps({
            "model": "llama-3.3-70b",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Classify a shell command run by a developer in a project directory.\n"
                        "SAFE: normal dev workflow — git (status/diff/log/add/commit/push/pull/checkout/branch), "
                        "docker/compose (ps/up/build/run/logs), package managers (npm/yarn/pnpm/pip/cargo/bun install/run/test), "
                        "build tools (make/gcc/cmake), cloud CLIs reading data (gcloud/aws/az logs/describe/list), "
                        "curl/wget for APIs, ssh to known hosts, test runners, linters, formatters.\n"
                        "UNSAFE: destructive git (push --force, reset --hard, clean -f); "
                        "reads sensitive files outside root (cat ~/.ssh/id_rsa, cat /etc/shadow); "
                        "docker --privileged or mounting host root; "
                        "cloud CLIs that modify infrastructure (delete/destroy/terminate); "
                        "curl posting local files to external hosts; system-wide package installs (apt install, brew install).\n"
                        "UNKNOWN: only if genuinely ambiguous.\n"
                        "Reply with exactly one word."
                    ),
                },
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
                "User-Agent": "bashbouncer/0.1",
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


def classify(cmd: str, root: str) -> tuple[str, str, str]:
    verdict, reason = prefilter(cmd, root)
    if verdict == "UNKNOWN":
        verdict, reason = classify_llm(cmd, root)
        return verdict, "llm", reason
    return verdict, "static", reason


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

    verdict, source, reason = classify(cmd, root)

    decision = {"SAFE": "allow", "UNSAFE": "deny"}.get(verdict, "ask")
    output: dict = {"hookSpecificOutput": {"permissionDecision": decision}}

    if decision == "deny":
        output["systemMessage"] = f"BashBouncer [{source}] blocked: {cmd} -- {reason}"
    elif decision == "ask":
        output["systemMessage"] = f"BashBouncer [{source}] unsure: {cmd} -- {reason}"

    print(json.dumps(output))


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

            verdict, source, reason = classify(cmd, root)
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
