"""Thin GitHub REST client (stdlib only).

Fetches the PR's changed files + their patches, the full file content at the
head SHA (needed for AST), and posts/updates a single sticky review comment.
"""
from __future__ import annotations

import base64
import json
import urllib.request
import urllib.error

from .config import Config

_MARKER = "<!-- rudra-review -->"


class GitHubClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.h = {
            "Authorization": f"Bearer {cfg.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "rudra-bot",
        }

    def _get(self, url: str):
        req = urllib.request.Request(url, headers=self.h)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def _send(self, url: str, payload: dict, method: str):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={**self.h, "Content-Type": "application/json"},
                                     method=method)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def pr_head_sha(self, repo: str, pr: int) -> str:
        return self._get(f"{self.cfg.github_api}/repos/{repo}/pulls/{pr}")["head"]["sha"]

    def changed_files(self, repo: str, pr: int) -> list[dict]:
        """Return [{filename, patch, status}], paginated."""
        files, page = [], 1
        while True:
            batch = self._get(
                f"{self.cfg.github_api}/repos/{repo}/pulls/{pr}/files?per_page=100&page={page}")
            files.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return files

    def file_content(self, repo: str, path: str, ref: str) -> str | None:
        try:
            data = self._get(
                f"{self.cfg.github_api}/repos/{repo}/contents/{path}?ref={ref}")
        except urllib.error.HTTPError:
            return None
        if data.get("encoding") == "base64":
            try:
                return base64.b64decode(data["content"]).decode("utf-8", "replace")
            except Exception:
                return None
        return None

    def upsert_comment(self, repo: str, pr: int, body: str) -> None:
        body = f"{_MARKER}\n{body}"
        comments = self._get(
            f"{self.cfg.github_api}/repos/{repo}/issues/{pr}/comments?per_page=100")
        for c in comments:
            if _MARKER in (c.get("body") or ""):
                self._send(f"{self.cfg.github_api}/repos/{repo}/issues/comments/{c['id']}",
                           {"body": body}, "PATCH")
                return
        self._send(f"{self.cfg.github_api}/repos/{repo}/issues/{pr}/comments",
                   {"body": body}, "POST")
