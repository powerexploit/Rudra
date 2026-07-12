"""Declarative regex rules.

Language-agnostic, line-scoped patterns for things an AST pass misses (JS/TS,
config files, string heuristics). These are intentionally *low* confidence and
almost always routed through LLM triage -- regex is where false positives are
born, so we lean on the funnel to filter them.

Contributors add detections by editing rules/llm.yaml, no Python required.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..models import Candidate, Severity
from .base import register

_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "llm.yaml"


class YamlRuleDetector:
    name = "yaml_rules"

    def __init__(self):
        self.rules = []
        if _RULES_PATH.exists():
            data = yaml.safe_load(_RULES_PATH.read_text()) or {}
            for r in data.get("rules", []):
                r["_re"] = re.compile(r["pattern"])
                self.rules.append(r)

    def scan(self, file_path: str, source: str, changed: set[int]) -> list[Candidate]:
        out = []
        lines = source.splitlines()
        for r in self.rules:
            exts = r.get("extensions")
            if exts and not any(file_path.endswith(e) for e in exts):
                continue
            for i, line in enumerate(lines, start=1):
                if changed and i not in changed:
                    continue
                if r["_re"].search(line):
                    out.append(Candidate(
                        rule_id=r["id"], owasp_id=r["owasp"], title=r["title"],
                        file_path=file_path, start_line=i, end_line=i,
                        code_snippet=line.strip(), severity=Severity(r["severity"]),
                        message=r["message"], remediation=r["remediation"],
                        detector_confidence=float(r.get("confidence", 0.4)),
                        deterministic=bool(r.get("deterministic", False)),
                    ))
        return out


register(YamlRuleDetector())
