#!/usr/bin/env python3
"""Reject unsafe tokens in corpus sources and artifacts."""

from __future__ import annotations

import re
import sys
from pathlib import Path


DENIED = (
    re.compile(rb"\bsocket\b", re.IGNORECASE),
    re.compile(rb"\burllib\b", re.IGNORECASE),
    re.compile(rb"\brequests\b", re.IGNORECASE),
    re.compile(rb"\bhttps?\b", re.IGNORECASE),
    re.compile(rb"\bcurl\b", re.IGNORECASE),
    re.compile(rb"\bwget\b", re.IGNORECASE),
    re.compile(rb"\bsubprocess\b", re.IGNORECASE),
    re.compile(rb"\bos\.system\b", re.IGNORECASE),
    re.compile(rb"\beval\s*\(", re.IGNORECASE),
    re.compile(rb"\bexec\s*\(", re.IGNORECASE),
    re.compile(rb"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    re.compile(rb"base64.{0,200}\b(?:eval|exec)\s*\(", re.IGNORECASE | re.DOTALL),
)


def files(path: Path):
    if path.is_file():
        yield path
    elif path.is_dir():
        yield from (p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def main(argv: list[str] | None = None) -> int:
    paths = [Path(value) for value in (argv or sys.argv[1:])]
    if not paths:
        print("usage: safety_lint.py PATH [PATH ...]", file=sys.stderr)
        return 2

    unsafe = False
    for root in paths:
        if not root.exists():
            print(f"missing path: {root}", file=sys.stderr)
            unsafe = True
            continue
        for path in files(root):
            data = path.read_bytes()
            for pattern in DENIED:
                if match := pattern.search(data):
                    print(f"{path}: denied token: {match.group().decode('ascii', 'replace')}", file=sys.stderr)
                    unsafe = True
    return int(unsafe)


if __name__ == "__main__":
    raise SystemExit(main())
