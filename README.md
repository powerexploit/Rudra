# 🛡️ Rudra

**An open-source GenAI/LLM security reviewer for pull requests.**
Rudra scans the code changed in a PR for the vulnerabilities in the
[OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/),
and comments back with the issue, its impact, a concrete fix, and a score — all
mapped to a stable OWASP category ID.

Rudra is built around a single obsession: **not crying wolf.** Most "AI code
reviewer" bots drown you in confident-but-wrong findings. Rudra treats a low
false-positive rate as the primary design constraint, not an afterthought.

---

## Why Rudra is different

The naive approach — hand the whole diff to an LLM and ask "find vulnerabilities" —
produces plausible, well-written, *wrong* findings at a high rate. Rudra never
does that. Instead it runs a **precision funnel**: a fast deterministic pass
*finds and grounds* candidates, and the LLM is used only to *confirm or kill*
them.

```
 PR opened
    │
    ▼
 ┌─────────────────────────────┐
 │ STAGE 1 — Deterministic      │   No LLM. Fast. High recall.
 │  • Python AST + taint        │   Produces CANDIDATES, each tagged with the
 │  • YAML regex rules           │   exact file/line, the quoted code, an OWASP
 │  • provider-secret scan       │   id, and a detector confidence.
 └──────────────┬──────────────┘
                │  (only lines the PR actually changed survive)
                ▼
 ┌─────────────────────────────┐
 │ STAGE 2 — LLM triage          │   Judges ONE candidate at a time. May not
 │  confirm / refute, grounded   │   invent new findings. Defaults to
 │  (optional N-sample vote)     │   false_positive. Returns confidence +
 └──────────────┬──────────────┘   reachability.
                │  (refuted → dropped)
                ▼
 ┌─────────────────────────────┐
 │ STAGE 3 — Adversarial verifier│   A second model call whose job is to
 │  "prove this is a FALSE pos"  │   DISPROVE the finding. Survives only if the
 └──────────────┬──────────────┘   attack fails.
                │
                ▼
 ┌─────────────────────────────┐
 │ Score + gate                  │   score = severity × confidence × reachability
 │  suppress < threshold, dedup  │   → 0–10 Rudra score
 └──────────────┬──────────────┘
                ▼
   SARIF (inline annotations) + Markdown PR comment + JSON
```

### The seven false-positive controls

1. **The LLM never freelances.** It only adjudicates candidates a deterministic
   detector already found. This removes the model's freedom to hallucinate
   issues.
2. **Everything is grounded.** Each candidate carries the exact code it's about;
   the model is told to cite the specific tokens and to lower confidence if it
   must assume facts it can't see.
3. **Adversarial verification.** An independent pass is *rewarded for disproving*
   the finding. Fragile alerts get knocked down. This is the biggest single win.
4. **Deterministic fast-path.** Near-certain findings (committed keys,
   `pickle.load`, `trust_remote_code=True`) skip the LLM entirely — no cost, no
   doubt.
5. **Diff-scoped.** Only lines the PR changed can be reported. Rudra never
   re-litigates the existing codebase.
6. **Confidence × reachability scoring.** Uncertainty visibly *lowers the score*
   instead of shouting CRITICAL. A CRITICAL sink the model is 60% sure about
   lands mid-range.
7. **Precision-over-recall default.** With no LLM configured, heuristic
   candidates are suppressed rather than guessed at; only deterministic findings
   report.

Self-consistency voting (`triage_samples`) is available for extra-noisy repos.

---

## What it detects

| OWASP | Detection (examples) | Path |
|-------|----------------------|------|
| LLM01 Prompt Injection | untrusted input concatenated into a prompt (f-string/`.format`/`+`) | AST → LLM |
| LLM02 Sensitive Info Disclosure | hardcoded OpenAI/Anthropic/HF/Google keys, secrets in prompts | deterministic |
| LLM03 Supply Chain | `trust_remote_code=True`, untrusted model loads | deterministic |
| LLM04 Data & Model Poisoning | `pickle.load`, `torch.load` w/o `weights_only`, `joblib.load` | deterministic |
| LLM05 Improper Output Handling | model output → `eval`/`exec`/`subprocess`/SQL/`innerHTML`/`dangerouslySetInnerHTML` | AST/regex → LLM |
| LLM06 Excessive Agency | `PythonREPLTool`, `ShellTool`, `load_tools(['terminal',…])`, `allow_dangerous_*=True` | deterministic |
| LLM07 System Prompt Leakage | credentials embedded in system prompts | regex → LLM |
| LLM08 Vector/Embedding | vector store without tenant isolation / auth | regex → LLM |
| LLM10 Unbounded Consumption | completion call with no `max_tokens`, HTTP calls with no `timeout` | AST/regex → LLM |

New detections are added either as Python AST checks or — no code required — as
declarative entries in [`rudra/rules/llm.yaml`](rudra/rules/llm.yaml).

---

## Quick start

### As a GitHub Action (the bot)

```yaml
# .github/workflows/rudra.yml
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  rudra:
    runs-on: ubuntu-latest
    steps:
      - uses: your-username/rudra@v0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          llm-api-key: ${{ secrets.RUDRA_LLM_API_KEY }}   # omit → deterministic-only
          fail-threshold-score: "7.0"
```

On every PR, Rudra posts a sticky review comment and uploads SARIF so findings
also appear as inline annotations in the **Files changed** tab.

### Locally

```bash
pip install .

# Scan files or directories on disk (whole-file mode):
rudra scan path/to/code

# Review a live PR (needs GITHUB_TOKEN):
export GITHUB_TOKEN=...            # repo read + PR write
export RUDRA_LLM_API_KEY=...       # optional; deterministic-only without it
rudra review your-username/rudra 1 2 3
```

---

## Configuration

All knobs live in [`rudra/config.py`](rudra/config.py) and are overridable by env var:

| Env / field | Default | What it does |
|-------------|---------|--------------|
| `RUDRA_LLM_PROVIDER` | `anthropic` | `anthropic` \| `openai` \| `none` |
| `RUDRA_LLM_MODEL` | `claude-sonnet-4-5` | triage/verifier model |
| `min_confidence` | `0.55` | drop findings below this final confidence |
| `min_score` | `4.0` | don't post findings scoring below this |
| `RUDRA_FAIL_SCORE` | `7.0` | fail CI if any finding ≥ this |
| `enable_verifier` | `True` | run the adversarial pass |
| `triage_samples` | `1` | self-consistency vote count |
| `require_llm_confirmation` | `True` | suppress heuristics when no LLM |

---

## Design notes & roadmap

- **Baselining:** the comment includes `/rudra ignore <rule-id>` as the intended
  interface for accepting a finding; wiring the comment-webhook handler + a
  `.rudra-baseline.yml` is the next milestone.
- **Reachability > pattern match:** the honest limit of static taint is
  cross-file / cross-function flow. The current AST pass is intra-file; the LLM
  stage compensates by reasoning about reachability, but a proper call-graph
  (e.g. via `semgrep --dataflow` or `CodeQL`) would raise Stage-1 precision.
- **Extending languages:** AST detectors are Python-only today; JS/TS is covered
  by regex rules. A tree-sitter backend is the clean path to real multi-language
  AST support.

Contributions welcome — start by adding a rule to `rudra/rules/llm.yaml` and a
fixture under `tests/fixtures/`.


## License
Apache-2.0.
