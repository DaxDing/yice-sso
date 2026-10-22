#!/usr/bin/env python3
"""Give every enabled caller declared in config/callers.v1.json a token in the yice-sso runtime .env.

Tokens are secrets, so they never live in the declaration: this script appends a fresh random
token for each enabled caller whose token_env has no value yet. Existing values are never read
into output, changed or removed; output names callers and variables only, never values.
Rotate a token by deleting its line from .env and deploying again.

Usage: deploy/ensure_tokens.py --callers PATH --env PATH [--execute]   plan, or append on --execute
       deploy/ensure_tokens.py --callers PATH --env-keys -             plan from key names on stdin
Exit:  0 ok · 1 failure · 2 usage
Stdlib only: runs on the ECS before the service venv is touched.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

ASSIGNMENT_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
EMPTY_VALUES = {"", "''", '""'}


def present_keys(lines: list[str]) -> set[str]:
    """Names assigned a non-empty value; a later empty assignment does not erase an earlier one."""
    keys = set()
    for line in lines:
        match = ASSIGNMENT_RE.match(line.strip())
        if match and match.group(2).strip() not in EMPTY_VALUES:
            keys.add(match.group(1))
    return keys


def missing_tokens(callers: dict, keys: set[str]) -> list[dict[str, str]]:
    """Enabled declared callers whose token variable has no value, in declaration order."""
    return [
        {"caller": name, "token_env": caller["token_env"]}
        for name, caller in callers["callers"].items()
        if caller.get("enabled", True) and caller["token_env"] not in keys
    ]


def append_tokens(env_path: Path, missing: list[dict[str, str]]) -> None:
    metadata = env_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RuntimeError(f"{env_path} must be a regular file readable by its owner only")
    text = env_path.read_text(encoding="utf-8")
    lines = [f"{item['token_env']}='{secrets.token_urlsafe(36)}'\n" for item in missing]
    descriptor = os.open(env_path, os.O_WRONLY | os.O_APPEND)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(("" if not text or text.endswith("\n") else "\n") + "".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--callers", type=Path, required=True, help="caller declaration (callers.v1.json)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--env", type=Path, help="runtime .env to check and, with --execute, append to")
    source.add_argument("--env-keys", choices=["-"], help="read assigned key names from stdin (plan only)")
    parser.add_argument("--execute", action="store_true", help="append missing tokens (requires --env)")
    args = parser.parse_args(argv)
    if args.execute and args.env is None:
        parser.error("--execute requires --env")
    try:
        callers = json.loads(args.callers.read_text(encoding="utf-8"))
        if args.env is not None:
            keys = present_keys(args.env.read_text(encoding="utf-8").splitlines())
        else:
            keys = {line.strip() for line in sys.stdin if line.strip()}
        missing = missing_tokens(callers, keys)
        if args.execute and missing:
            append_tokens(args.env, missing)
            still = missing_tokens(callers, present_keys(args.env.read_text(encoding="utf-8").splitlines()))
            if still:
                raise RuntimeError("readback still misses tokens for: " + ", ".join(i["caller"] for i in still))
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "mode": "execute" if args.execute else "plan",
                "missing": missing,
                "generated": [item["caller"] for item in missing] if args.execute else [],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
