"""Scoring and gating.

Rudra score (0..10) = severity_weight * confidence * reachability_factor.

Confidence and reachability can only ever *demote* a finding, never inflate it
past its severity ceiling. A CRITICAL sink that the model is only 60% sure about
and that untrusted input barely reaches ends up mid-range -- which is the whole
point: uncertainty visibly lowers the score instead of screaming CRITICAL.
"""
from __future__ import annotations

from .config import Config
from .models import Finding, Severity, SEVERITY_WEIGHT


def score(f: Finding) -> float:
    base = SEVERITY_WEIGHT[f.severity]
    # reachability dampens but never zeroes: floor at 0.5 so a real bug with
    # unclear reachability still surfaces for a human.
    reach = 0.5 + 0.5 * max(0.0, min(1.0, f.reachability))
    conf = max(0.0, min(1.0, f.confidence))
    return round(min(10.0, base * conf * reach), 1)


def band(s: float) -> Severity:
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    if s >= 2.0:
        return Severity.LOW
    return Severity.INFO


def apply_scores_and_gate(findings: list[Finding], cfg: Config) -> list[Finding]:
    kept = []
    for f in findings:
        f.score = score(f)
        if f.confidence < cfg.min_confidence:
            continue
        if f.score < cfg.min_score:
            continue
        kept.append(f)
    kept.sort(key=lambda x: x.score, reverse=True)
    return dedup(kept)


def dedup(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicates on (file, rule, line); keep the highest score."""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.file_path, f.rule_id, f.start_line)
        if key not in seen or f.score > seen[key].score:
            seen[key] = f
    return sorted(seen.values(), key=lambda x: x.score, reverse=True)


def should_fail_ci(findings: list[Finding], cfg: Config) -> bool:
    return any(f.score >= cfg.fail_threshold_score for f in findings)
