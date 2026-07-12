"""Rudra entrypoint.

Modes:
  rudra review <owner/repo> <pr_number> [<pr_number> ...]   # GitHub PR review
  rudra scan <path> [<path> ...]                            # local files/dirs
  rudra                                                     # GitHub Action (env-driven)

Exit code is non-zero when a finding meets `fail_threshold_score`, so it can
gate CI.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .config import Config
from .engine import run_review
from . import report as R


def _emit(result, cfg: Config, gh=None):
    if cfg.write_sarif:
        Path(cfg.sarif_path).write_text(R.to_sarif(result))
    md = R.to_markdown(result)
    if gh and cfg.post_comment and result.pr_number:
        try:
            gh.upsert_comment(result.repo, result.pr_number, md)
        except Exception as e:  # never fail the job just because commenting failed
            print(f"[rudra] could not post comment: {e}", file=sys.stderr)
    print(md)
    for line in result.logs:
        print(f"[rudra] {line}", file=sys.stderr)


def review_pr(repo: str, pr: int, cfg: Config) -> bool:
    from .github_client import GitHubClient
    gh = GitHubClient(cfg)
    # Write an empty-but-valid SARIF first, so the upload step always has a file
    # even if something below throws unexpectedly.
    if cfg.write_sarif and not Path(cfg.sarif_path).exists():
        Path(cfg.sarif_path).write_text(R.to_sarif(
            R.ReviewResult(repo=repo, pr_number=pr, head_sha="")))
    head = gh.pr_head_sha(repo, pr)
    files = gh.changed_files(repo, pr)
    result = run_review(repo, pr, files,
                        lambda p: gh.file_content(repo, p, head), cfg, head)
    _emit(result, cfg, gh)
    from .scoring import should_fail_ci
    return should_fail_ci(result.findings, cfg)


def scan_local(paths: list[str], cfg: Config) -> bool:
    files = []
    for p in paths:
        pth = Path(p)
        targets = pth.rglob("*") if pth.is_dir() else [pth]
        for t in targets:
            if t.is_file() and any(str(t).endswith(e) for e in cfg.include_extensions):
                files.append({"filename": str(t), "patch": None})  # no diff -> whole file
    contents = {f["filename"]: Path(f["filename"]).read_text(errors="replace") for f in files}
    result = run_review("local", 0, files, lambda p: contents.get(p), cfg)
    _emit(result, cfg)
    from .scoring import should_fail_ci
    return should_fail_ci(result.findings, cfg)


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    cfg = Config()

    # GitHub Action mode: no CLI args, derive from environment.
    if not argv and os.getenv("GITHUB_REPOSITORY") and os.getenv("RUDRA_PR_NUMBER"):
        failed = review_pr(os.environ["GITHUB_REPOSITORY"],
                           int(os.environ["RUDRA_PR_NUMBER"]), cfg)
        return 1 if failed else 0

    if not argv:
        print(__doc__)
        return 0

    cmd, rest = argv[0], argv[1:]
    if cmd == "review":
        repo, prs = rest[0], [int(x) for x in rest[1:]]
        failed = any(review_pr(repo, pr, cfg) for pr in prs)
        return 1 if failed else 0
    if cmd == "scan":
        return 1 if scan_local(rest, cfg) else 0

    print(f"unknown command: {cmd}\n{__doc__}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
