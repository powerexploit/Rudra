"""Output formatting: SARIF (for GitHub code-scanning inline annotations),
Markdown (for the PR summary comment), and JSON (machine-readable)."""
from __future__ import annotations

import json

from .models import ReviewResult, Finding, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
}
_EMOJI = {
    Severity.CRITICAL: "\U0001F534", Severity.HIGH: "\U0001F7E0",
    Severity.MEDIUM: "\U0001F7E1", Severity.LOW: "\U0001F535", Severity.INFO: "\u26AA",
}


def to_json(result: ReviewResult) -> str:
    return json.dumps({
        "repo": result.repo, "pr_number": result.pr_number,
        "head_sha": result.head_sha, "stats": result.stats,
        "logs": result.logs,
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


def to_sarif(result: ReviewResult) -> str:
    rules, rule_ids = [], set()
    for f in result.findings:
        if f.rule_id in rule_ids:
            continue
        rule_ids.add(f.rule_id)
        rules.append({
            "id": f.rule_id,
            "name": f.title.replace(" ", ""),
            "shortDescription": {"text": f.title},
            "properties": {"owasp-llm": f.owasp_id, "tags": ["security", f.owasp_id]},
        })
    sarif_results = []
    for f in result.findings:
        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[Severity(f.severity)],
            "message": {"text": f"[{f.owasp_id}] {f.impact}\n\nRemediation: {f.remediation}\n"
                                f"(Rudra score {f.score}/10, confidence {f.confidence})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.start_line, "endLine": max(f.start_line, f.end_line)},
                }
            }],
            "properties": {"score": f.score, "confidence": f.confidence,
                           "reachability": f.reachability, "owasp": f.owasp_id},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Rudra",
                "informationUri": "https://github.com/your-username/rudra",
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }, indent=2)


def to_markdown(result: ReviewResult) -> str:
    s = result.stats
    lines = ["## \U0001F6E1\uFE0F Rudra — GenAI/LLM Security Review", ""]
    if not result.findings:
        lines += [
            "No LLM security issues found in the changed lines. \u2705", "",
            f"<sub>Scanned {s.get('files', 0)} file(s) · "
            f"{s.get('candidates', 0)} candidate(s) raised · "
            f"{s.get('suppressed', 0)} filtered as false positives.</sub>",
        ]
        return "\n".join(lines)

    crit = sum(1 for f in result.findings if f.score >= 7)
    lines.append(f"Found **{len(result.findings)}** issue(s) "
                 f"({crit} high/critical) mapped to the OWASP LLM Top 10.\n")
    lines.append("| Sev | Score | OWASP | Issue | Location |")
    lines.append("|-----|-------|-------|-------|----------|")
    for f in result.findings:
        sev = Severity(f.severity)
        loc = f"`{f.file_path}:{f.start_line}`"
        lines.append(f"| {_EMOJI[sev]} | {f.score}/10 | {f.owasp_id} | {f.title} | {loc} |")
    lines.append("")

    for f in result.findings:
        sev = Severity(f.severity)
        lines += [
            f"### {_EMOJI[sev]} {f.title} — `{f.owasp_id}`  ·  score {f.score}/10",
            f"**Location:** `{f.file_path}:{f.start_line}`  |  "
            f"**Confidence:** {int(f.confidence*100)}%  |  "
            f"**Reachability:** {int(f.reachability*100)}%", "",
            "```", f.code_snippet, "```",
            f"**Impact.** {f.impact}", "",
            f"**Remediation.** {f.remediation}", "",
        ]
        if f.evidence:
            lines.append(f"<sub>Evidence: {f.evidence}</sub>")
        if f.verifier_note:
            lines.append(f"<sub>Reviewed against counter-argument: {f.verifier_note}</sub>")
        lines.append("\n---\n")

    lines.append(
        f"<sub>Funnel: {s.get('candidates', 0)} candidates → "
        f"{s.get('confirmed', 0)} confirmed → {s.get('final', 0)} reported · "
        f"{s.get('suppressed', 0)} suppressed as likely false positives. "
        f"Reply `/rudra ignore <rule-id>` to baseline a finding.</sub>")
    return "\n".join(lines)
