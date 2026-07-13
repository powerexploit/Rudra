"""Rudra configuration.

Every knob that trades recall for precision lives here so tuning the
false-positive rate is a config change, not a code change.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# Sensible per-provider default so an empty RUDRA_LLM_MODEL doesn't silently
# send an Anthropic model name to OpenAI (or vice versa).
DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5",
    "openai": "gpt-4o-mini",
}


def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    # ---- LLM provider ----
    # "anthropic", "openai", or "none" (deterministic-only mode).
    # Left blank by default so __post_init__ can auto-detect it from whichever
    # vendor API key is actually present, instead of assuming one vendor.
    llm_provider: str = os.getenv("RUDRA_LLM_PROVIDER", "")
    llm_model: str = os.getenv("RUDRA_LLM_MODEL", "")
    llm_api_key: str | None = os.getenv("RUDRA_LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY")
    llm_temperature: float = 0.0      # determinism matters for reproducible reviews
    llm_max_tokens: int = 1500

    # ---- Funnel behaviour (the FP-control dials) ----
    # If no LLM is available, drop non-deterministic candidates instead of
    # guessing. Precision over recall by default.
    require_llm_confirmation: bool = _bool_env("RUDRA_REQUIRE_LLM_CONFIRMATION", True)
    # Run the adversarial verifier pass. Biggest single FP reducer; costs 1 extra call.
    enable_verifier: bool = _bool_env("RUDRA_ENABLE_VERIFIER", True)
    # Self-consistency: run triage N times, keep only if the majority confirm.
    # 1 = off. 3 is a good high-signal setting for noisy repos.
    triage_samples: int = int(os.getenv("RUDRA_TRIAGE_SAMPLES", "1"))

    # ---- Gating thresholds ----
    # Minimum final confidence to report at all.
    min_confidence: float = float(os.getenv("RUDRA_MIN_CONFIDENCE", "0.55"))
    # Minimum Rudra score (0..10) to post to the PR.
    min_score: float = float(os.getenv("RUDRA_MIN_SCORE", "4.0"))
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

    def __post_init__(self) -> None:
        if self.llm_provider and self.llm_provider not in ("anthropic", "openai", "none"):
            raise ValueError(
                f"llm_provider must be 'anthropic', 'openai', or 'none', got {self.llm_provider!r}"
            )
        if not self.llm_provider:
            self.llm_provider = self._detect_provider()
        if not self.llm_model:
            self.llm_model = DEFAULT_MODELS.get(self.llm_provider, "")

    @staticmethod
    def _detect_provider() -> str:
        """Pick a provider from whichever vendor key is actually set.

        Only used when llm-provider is left blank. Falls back to 'none'
        (deterministic-only) when there's no key at all, and refuses to
        guess when the signal is ambiguous (both vendor keys set, or only
        the generic RUDRA_LLM_API_KEY, which isn't tied to a vendor).
        """
        has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY"))
        has_openai = bool(os.getenv("OPENAI_API_KEY"))
        if has_anthropic and not has_openai:
            return "anthropic"
        if has_openai and not has_anthropic:
            return "openai"
        if has_anthropic and has_openai:
            raise ValueError(
                "Both ANTHROPIC_API_KEY and OPENAI_API_KEY are set — "
                "set llm-provider explicitly to pick one."
            )
        if os.getenv("RUDRA_LLM_API_KEY"):
            raise ValueError(
                "RUDRA_LLM_API_KEY is set but llm-provider is not — "
                "set llm-provider ('anthropic' or 'openai') so Rudra knows "
                "which API that key belongs to."
            )
        return "none"

    def llm_available(self) -> bool:
        return self.llm_provider != "none" and bool(self.llm_api_key)
