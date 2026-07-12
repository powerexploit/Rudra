"""Hardcoded AI-provider secret detection (LLM02 / LLM07).

Secrets are the one category where a regex is near-certain, so these are marked
`deterministic=True` and skip LLM triage entirely. We still verify format shape
to avoid flagging obvious placeholders.
"""
from __future__ import annotations

import re

from ..models import Candidate, Severity
from .base import register

# (regex, provider). Patterns intentionally require realistic length/charset.
PATTERNS = [
    (re.compile(r"sk-ant-[a-zA-Z0-9\-_]{24,}"), "Anthropic API key"),
    (re.compile(r"sk-(?:proj-)?[a-zA-Z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google AI / GCP key"),
    (re.compile(r"hf_[a-zA-Z0-9]{30,}"), "Hugging Face token"),
    (re.compile(r"r8_[a-zA-Z0-9]{30,}"), "Replicate token"),
    (re.compile(r"co-[a-zA-Z0-9]{40,}"), "Cohere key"),
]
# Direct assignment of a literal to a provider key attribute.
ASSIGN_RE = re.compile(r"(?i)(openai|anthropic)\.api_key\s*=\s*[\"'][^\"']+[\"']")
PLACEHOLDER = re.compile(r"(?i)(your|example|xxxx|placeholder|<.*>|dummy|test)")


class SecretDetector:
    name = "secrets"

    def scan(self, file_path: str, source: str, changed: set[int]) -> list[Candidate]:
        out = []
        for i, line in enumerate(source.splitlines(), start=1):
            if changed and i not in changed:
                continue
            provider = None
            for rx, name in PATTERNS:
                m = rx.search(line)
                if m and not PLACEHOLDER.search(m.group(0)):
                    provider = name
                    break
            if not provider and ASSIGN_RE.search(line) and not PLACEHOLDER.search(line):
                provider = "LLM provider key (inline assignment)"
            if provider:
                out.append(Candidate(
                    rule_id="RUDRA-SECRET-LLM-KEY", owasp_id="LLM02:2025",
                    title=f"Hardcoded {provider}", file_path=file_path,
                    start_line=i, end_line=i,
                    code_snippet=re.sub(r"(sk-[a-zA-Z0-9\-_]{6})[a-zA-Z0-9\-_]+", r"\1...[redacted]", line.strip()),
                    severity=Severity.CRITICAL,
                    message="A live-looking provider credential is committed in source. Anyone with "
                            "repo access (or a leak) can run up cost and access your data.",
                    remediation="Remove the key, rotate it immediately, and load it from an environment "
                                "variable or secrets manager. Add a pre-commit secret scanner.",
                    detector_confidence=0.95, deterministic=True,
                ))
        return out


register(SecretDetector())
