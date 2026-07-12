"""The funnel orchestrator.

    detectors (stage 1)  ->  triage (stage 2)  ->  verify (stage 3)  ->  score+gate

Deterministic candidates (leaked keys, pickle.load, etc.) skip the LLM stages
because they are near-certain; everything heuristic must earn its place by
surviving triage and the adversarial verifier.
"""
from __future__ import annotations

from .config import Config
from .detectors import get_detectors
from .detectors.base import snippet
from .diff import changed_lines
from .llm import LLMClient, triage, verify
from .models import Candidate, Finding, ReviewResult
from .scoring import apply_scores_and_gate

# import detectors package so they self-register
from . import detectors as _  # noqa: F401


def _skip(path: str, cfg: Config) -> bool:
    if not any(path.endswith(e) for e in cfg.include_extensions):
        return True
    return any(sub in path for sub in cfg.exclude_path_substrings)


def _candidate_to_finding(c: Candidate) -> Finding:
    """Promote a deterministic candidate straight to a Finding."""
    return Finding(
        rule_id=c.rule_id, owasp_id=c.owasp_id, title=c.title,
        file_path=c.file_path, start_line=c.start_line, end_line=c.end_line,
        code_snippet=c.code_snippet, severity=c.severity,
        impact=c.message, remediation=c.remediation,
        confidence=c.detector_confidence, reachability=0.9,
        evidence="Deterministic detector (no LLM adjudication required).",
    )


def run_review(repo: str, pr: int, files: list[dict],
               get_content, cfg: Config, head_sha: str = "") -> ReviewResult:
    """`files`   : list of {filename, patch}
       `get_content(path)` : returns full file text at head, or None."""
    result = ReviewResult(repo=repo, pr_number=pr, head_sha=head_sha)
    detectors = get_detectors(cfg.enabled_detectors)
    llm_ready = cfg.llm_available()
    client = LLMClient(cfg) if llm_ready else None

    all_candidates: list[Candidate] = []
    scanned = 0
    for fmeta in files[: cfg.max_files]:
        path = fmeta["filename"]
        if _skip(path, cfg):
            continue
        source = get_content(path)
        if not source:
            continue
        scanned += 1
        changed = changed_lines(fmeta.get("patch"))
        for det in detectors:
            for c in det.scan(path, source, changed):
                # attach surrounding context for the LLM
                c.context = snippet(source, c.start_line, c.end_line, pad=cfg.context_lines)
                all_candidates.append(c)

    result.logs.append(f"Stage 1: {len(all_candidates)} candidate(s) from {scanned} file(s).")

    findings: list[Finding] = []
    confirmed = suppressed = 0
    for c in all_candidates:
        if c.deterministic:
            findings.append(_candidate_to_finding(c))
            confirmed += 1
            continue
        if not llm_ready:
            if cfg.require_llm_confirmation:
                suppressed += 1          # precision over recall when no model
                continue
            findings.append(_candidate_to_finding(c))
            continue
        # Stage 2: triage
        f = triage(client, cfg, c)
        if f is None:
            suppressed += 1
            continue
        # Stage 3: adversarial verify
        if cfg.enable_verifier:
            f = verify(client, f)
            if f is None:
                suppressed += 1
                continue
        findings.append(f)
        confirmed += 1

    result.logs.append(f"Stage 2/3: {confirmed} confirmed, {suppressed} suppressed as likely FP.")

    final = apply_scores_and_gate(findings, cfg)
    result.findings = final
    result.stats = {
        "files": scanned, "candidates": len(all_candidates),
        "confirmed": confirmed, "suppressed": suppressed + (confirmed - len(final)),
        "final": len(final),
        "llm_used": llm_ready,
    }
    result.logs.append(f"Reported {len(final)} finding(s) after scoring/gating.")
    return result
