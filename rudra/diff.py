"""Parse GitHub's per-file unified-diff `patch` into the set of new-file
line numbers that were added or modified.

We only ever *report* on these lines. AST/rule analysis still runs over the
full file (you can't parse a half-function), but a finding is discarded unless
its line falls inside the changed set. This is a core false-positive control:
Rudra never nags about pre-existing code a PR didn't touch.
"""
from __future__ import annotations

import re

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(patch: str | None) -> set[int]:
    """Return new-file line numbers that are added ('+') in the patch."""
    if not patch:
        return set()
    result: set[int] = set()
    new_line = 0
    for raw in patch.splitlines():
        m = HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            result.add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            # deletion: does not advance the new-file cursor
            continue
        else:
            # context line
            new_line += 1
    return result
