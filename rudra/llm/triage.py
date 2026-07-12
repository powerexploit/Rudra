"""Stage 2: LLM triage.

Turns a Candidate into a Finding (or None if refuted). Optionally runs several
independent samples and takes a majority vote (self-consistency) for extra
robustness on noisy repos.
"""
from __future__ import annotations

from ..config import Config
from ..models import Candidate, Finding, Severity
from .client import LLMClient, parse_json
from .prompts import TRIAGE_SYSTEM, TRIAGE_USER


def _one_pass(client: LLMClient, c: Candidate) -> dict | None:
    user = TRIAGE_USER.format(
        owasp_id=c.owasp_id, title=c.title, message=c.message,
        file_path=c.file_path, start_line=c.start_line, end_line=c.end_line,
        code_snippet=c.code_snippet, context=c.context or "(none provided)",
    )
    return parse_json(client.complete(TRIAGE_SYSTEM, user))


def triage(client: LLMClient, cfg: Config, c: Candidate) -> Finding | None:
    verdicts, confs, results = [], [], []
    for _ in range(max(1, cfg.triage_samples)):
        r = _one_pass(client, c)
        if not r:
            continue
        results.append(r)
        verdicts.append(r.get("verdict", "false_positive"))
        confs.append(float(r.get("confidence", 0.0)))

    if not results:
        return None  # model gave nothing parseable -> do not report

    tp = verdicts.count("true_positive")
    if tp <= len(verdicts) / 2:            # majority must confirm
        return None

    # aggregate over the confirming samples
    tp_results = [r for r, v in zip(results, verdicts) if v == "true_positive"]
    best = max(tp_results, key=lambda r: float(r.get("confidence", 0)))
    conf = sum(float(r.get("confidence", 0)) for r in tp_results) / len(tp_results)

    try:
        sev = Severity(best.get("severity", c.severity.value))
    except ValueError:
        sev = c.severity

    return Finding(
        rule_id=c.rule_id, owasp_id=c.owasp_id, title=c.title,
        file_path=c.file_path, start_line=c.start_line, end_line=c.end_line,
        code_snippet=c.code_snippet, severity=sev,
        impact=best.get("impact", c.message),
        remediation=best.get("remediation", c.remediation),
        confidence=round(conf, 2),
        reachability=float(best.get("reachability", 0.5)),
        evidence=best.get("evidence", ""),
    )
