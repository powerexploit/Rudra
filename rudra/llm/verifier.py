"""Stage 3: adversarial verification.

A second model call whose job is to *disprove* the finding. If it succeeds
(verdict == false_positive with real confidence), the finding is dropped. If it
fails, the finding survives but records the strongest counter-argument, and its
confidence is blended down slightly to reflect residual doubt.

This asymmetry -- one pass tries to confirm, an independent pass tries to
refute -- is what stops confident-but-wrong single-shot alerts.
"""
from __future__ import annotations

from ..models import Finding
from .client import LLMClient, parse_json
from .prompts import VERIFIER_SYSTEM, VERIFIER_USER


def verify(client: LLMClient, f: Finding) -> Finding | None:
    user = VERIFIER_USER.format(
        owasp_id=f.owasp_id, title=f.title, impact=f.impact,
        file_path=f.file_path, start_line=f.start_line, end_line=f.end_line,
        code_snippet=f.code_snippet, context=f.evidence or "(none)",
    )
    r = parse_json(client.complete(VERIFIER_SYSTEM, user))
    if not r:
        return f  # verifier failed to answer -> keep finding, don't lose signal

    counter = r.get("strongest_counterargument", "")
    verdict = r.get("verdict", "confirmed")
    vconf = float(r.get("confidence", 0.5))

    if verdict == "false_positive" and vconf >= 0.6:
        return None  # refuted with conviction -> suppress

    f.verifier_note = counter
    # residual-doubt penalty: a strong-but-failed counter still lowers confidence
    if verdict == "false_positive":
        f.confidence = round(f.confidence * (1 - 0.4 * vconf), 2)
    return f
