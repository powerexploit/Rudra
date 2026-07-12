"""Detector interface.

A detector is a pure function of (file_path, source, changed_lines) -> [Candidate].
It must be side-effect free and never call the network, so Stage 1 stays fast,
deterministic, and unit-testable. All LLM work happens later in the funnel.
"""
from __future__ import annotations

from typing import Protocol

from ..models import Candidate


class Detector(Protocol):
    name: str

    def scan(self, file_path: str, source: str, changed: set[int]) -> list[Candidate]:
        ...


_REGISTRY: dict[str, Detector] = {}


def register(detector: Detector) -> None:
    _REGISTRY[detector.name] = detector


def get_detectors(enabled: tuple[str, ...]) -> list[Detector]:
    return [_REGISTRY[n] for n in enabled if n in _REGISTRY]


def within_changed(line: int, changed: set[int]) -> bool:
    # Empty set means "whole file" (e.g. local scan mode with no diff).
    return not changed or line in changed


def snippet(source: str, start: int, end: int, pad: int = 0) -> str:
    lines = source.splitlines()
    lo = max(0, start - 1 - pad)
    hi = min(len(lines), end + pad)
    return "\n".join(lines[lo:hi])
