"""Rudra configuration.

Every knob that trades recall for precision lives here so tuning the
false-positive rate is a config change, not a code change.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    # ---- LLM provider ----
    # "anthropic", "openai", or "none" (deterministic-only mode).
    llm_provider: str = os.getenv("RUDRA_LLM_PROVIDER", "anthropic")
    llm_model: str = os.getenv("RUDRA_LLM_MODEL", "claude-sonnet-4-5")
    llm_api_key: str | None = os.getenv("RUDRA_LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY")
    llm_temperature: float = 0.0      # determinism matters for reproducible reviews
    llm_max_tokens: int = 1500

    # ---- Funnel behaviour (the FP-control dials) ----
    # If no LLM is available, drop non-deterministic candidates instead of
    # guessing. Precision over recall by default.
    require_llm_confirmation: bool = True
    # Run the adversarial verifier pass. Biggest single FP reducer; costs 1 extra call.
    enable_verifier: bool = True
    # Self-consistency: run triage N times, keep only if the majority confirm.
    # 1 = off. 3 is a good high-signal setting for noisy repos.
    triage_samples: int = 1

    # ---- Gating thresholds ----
    # Minimum final confidence to report at all.
    min_confidence: float = 0.55
    # Minimum Rudra score (0..10) to post to the PR.
    min_score: float = 4.0
    # Fail the CI check (non-zero exit) if any finding is at/above this score.
    fail_threshold_score: float = float(os.getenv("RUDRA_FAIL_SCORE", "7.0"))

    # ---- Scope ----
    include_extensions: tuple = (".py", ".ipynb", ".js", ".ts", ".tsx", ".yaml", ".yml", ".toml", ".env")
    # Files matching these substrings are skipped (tests, vendored, fixtures).
    exclude_path_substrings: tuple = ("/test", "test_", "/vendor/", "/node_modules/", "/.venv/", "rudra/tests/")
    max_files: int = 60               # safety cap for huge PRs
    context_lines: int = 8            # lines of surrounding code sent to the LLM

    # ---- GitHub ----
    github_token: str | None = os.getenv("GITHUB_TOKEN")
    github_api: str = os.getenv("GITHUB_API_URL", "https://api.github.com")
    post_comment: bool = True
    write_sarif: bool = True
    sarif_path: str = os.getenv("RUDRA_SARIF_PATH", "rudra.sarif")

    enabled_detectors: tuple = ("python_ast", "yaml_rules", "secrets")

    def llm_available(self) -> bool:
        return self.llm_provider != "none" and bool(self.llm_api_key)
