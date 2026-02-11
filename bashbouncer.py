#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["httpx"]
# ///

import json
import os
import re
import shlex
import sys

import httpx

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
    "sudo su kill killall shutdown reboot halt poweroff curl wget scp rsync ssh "
    "nc ncat socat apt yum dnf brew pip npm yarn pnpm make gcc cc install mount "
    "umount fdisk parted useradd userdel usermod groupadd crontab at systemctl "
    "service launchctl defaults dscl pkill dd mkfs xargs".split()
)

FILE_OPS = frozenset(
    "rm rmdir mv cp chmod chown chgrp ln unlink truncate shred tee touch mkdir".split()
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


def prefilter(cmd: str, root: str) -> str:
    # Subshells / command substitution -> UNKNOWN
    if re.search(r"\$\(|`|<\(|>\(", cmd):
        return "UNKNOWN"

    # Redirects: check target against root
    redir = re.search(r">>?\s*(\S+)", cmd)
    if redir:
        target = redir.group(1)
        if root and is_within_root(target, root):
            return "SAFE"
        return "UNSAFE"

    # Split on pipes / chains
    segments = re.split(r"[|;&]{1,2}", cmd)

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        base = get_base_cmd(seg)

        if base in UNSAFE_ALWAYS:
            return "UNSAFE"

        if base in FILE_OPS:
            if not root or not check_paths_in_root(seg, root):
                return "UNSAFE"
            continue

        if base not in SAFE_CMDS:
            return "UNKNOWN"

    return "SAFE"


def classify_llm(cmd: str, root: str, client: httpx.Client) -> str:
    try:
        resp = client.post(
            API,
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={
                "model": "llama-3.3-70b",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Classify shell commands. "
                            "SAFE = read-only, informational, or writes only within the allowed root directory. "
                            "UNSAFE = writes outside the root, network access, privilege escalation, or system modification. "
                            "Reply with one word: SAFE or UNSAFE."
                        ),
                    },
                    {"role": "user", "content": f"Root: {root}\nCommand: {cmd}"},
                ],
                "temperature": 0,
                "max_tokens": 5,
            },
            timeout=10,
        )
        text = resp.json()["choices"][0]["message"]["content"]
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)
        text = text.strip().upper()
        if "UNSAFE" in text:
            return "UNSAFE"
        if "SAFE" in text:
            return "SAFE"
    except Exception:
        pass
    return "UNSAFE"


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: bashbouncer <commands.jsonl>", file=sys.stderr)
        print('Input: JSONL, one object per line: {"command": "...", "root": "..."}', file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"Error: not a file: {path}", file=sys.stderr)
        sys.exit(1)

    regex_calls = 0
    llm_calls = 0

    with open(path) as f, httpx.Client() as client:
        for line in f:
            line = line.strip()
            if not line:
                continue

            obj = json.loads(line)
            cmd = obj["command"]
            root = obj.get("root", "")

            verdict = prefilter(cmd, root)
            if verdict == "UNKNOWN":
                verdict = classify_llm(cmd, root, client)
                llm_calls += 1
            else:
                regex_calls += 1

            print(json.dumps({"command": cmd, "root": root, "verdict": verdict}))

    print(f"--- stats: regex={regex_calls}  llm={llm_calls} ---", file=sys.stderr)


if __name__ == "__main__":
    main()
