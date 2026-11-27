#!/usr/bin/env python3
"""Require an explicit cache setting for each Go setup step in a release workflow."""

import argparse
from pathlib import Path
import re
import sys


STEP = re.compile(r"^( *)-\s+")
SETUP_GO = re.compile(r"\buses:\s*['\"]?actions/setup-go@")


def check(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    problems = []
    count = 0
    for index, line in enumerate(lines):
        if not SETUP_GO.search(line):
            continue
        count += 1
        use_indent = len(line) - len(line.lstrip(" "))
        if match := STEP.match(line):
            step_indent = len(match.group(1))
        else:
            step_indent = next(
                (len(match.group(1)) for prior in reversed(lines[:index])
                 if (match := STEP.match(prior)) and len(match.group(1)) < use_indent),
                -1,
            )
        if step_indent < 0:
            problems.append(f"{path}:{index + 1}: Go setup is outside a step")
            continue
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            indent = len(candidate) - len(candidate.lstrip(" "))
            if candidate.strip() and indent <= step_indent:
                break
            end += 1
        with_indent = step_indent + 2
        cache_values = []
        in_with = False
        for candidate in lines[index + 1:end]:
            indent = len(candidate) - len(candidate.lstrip(" "))
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            if indent == with_indent:
                in_with = candidate.strip() == "with:"
            elif in_with and indent == with_indent + 2:
                match = re.fullmatch(r"cache:\s*(.*?)\s*(?:#.*)?", candidate.strip())
                if match:
                    cache_values.append(match.group(1))
        if cache_values != ["false"]:
            problems.append(f"{path}:{index + 1}: Go setup requires with.cache: false")
    if not count:
        problems.append(f"{path}: no Go setup steps found")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow", type=Path)
    args = parser.parse_args()
    problems = check(args.workflow)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"ok: {args.workflow} Go setup steps use no shared cache")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
