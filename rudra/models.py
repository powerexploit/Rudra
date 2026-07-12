"""Data models shared across the Rudra pipeline.

The pipeline flows: Candidate -> (LLM triage) -> (verifier) -> Finding.
Keeping these as plain dataclasses makes every stage easy to test in isolation.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Relative weights used by scoring.py. Deliberately spread out so severity
# dominates the score but confidence/reachability can still demote a finding.
SEVERITY_WEIGHT = {
    Severity.INFO: 1.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 5.5,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.5,
}


@dataclass
class Candidate:
    """A *potential* issue produced by a Stage-1 detector.

    A candidate is never shown to the user directly. It is either promoted to a
    Finding by the LLM triage/verifier stages, or (for deterministic detectors)
    promoted straight through with high confidence.
    """
    rule_id: str                 # e.g. "RUDRA-AST-OUTPUT-EXEC"
    owasp_id: str                # e.g. "LLM05:2025"
    title: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str            # the exact source lines this alert is about
    severity: Severity
    message: str                 # why the detector fired
    remediation: str
    # detector's prior belief this is real, before any LLM sees it (0..1).
    detector_confidence: float = 0.5
    # if True, skip the LLM entirely (near-certain, e.g. a leaked key).
    deterministic: bool = False
    # extra context handed to the LLM (surrounding function, imports, etc.)
    context: str = ""


@dataclass
class Finding:
    """A confirmed issue, ready to report."""
    rule_id: str
    owasp_id: str
    title: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    severity: Severity
    impact: str
    remediation: str
    confidence: float            # final confidence after triage+verify (0..1)
    reachability: float          # 0..1, is attacker input plausibly reaching this?
    score: float = 0.0           # 0..10 Rudra score, set by scoring.py
    evidence: str = ""           # the model's grounded justification
    verifier_note: str = ""      # strongest counter-argument that failed to kill it

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ReviewResult:
    repo: str
    pr_number: int
    head_sha: str
    findings: list[Finding] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    # counts for the funnel, surfaced in the report for transparency.
    stats: dict = field(default_factory=dict)
