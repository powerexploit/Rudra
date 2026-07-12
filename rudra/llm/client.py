"""Minimal provider-agnostic LLM client (Anthropic + OpenAI-compatible).

Uses only the stdlib so Rudra has no hard runtime dependency on a vendor SDK.
temperature=0 for reproducible reviews. Returns raw text; parsing is the
caller's job.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

from ..config import Config


class LLMClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def complete(self, system: str, user: str) -> str:
        if not self.cfg.llm_available():
            raise RuntimeError("LLM not configured")
        if self.cfg.llm_provider == "anthropic":
            return self._anthropic(system, user)
        return self._openai(system, user)

    def _post(self, url: str, headers: dict, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())

    def _anthropic(self, system: str, user: str) -> str:
        body = self._post(
            "https://api.anthropic.com/v1/messages",
            {"content-type": "application/json",
             "x-api-key": self.cfg.llm_api_key,
             "anthropic-version": "2023-06-01"},
            {"model": self.cfg.llm_model, "max_tokens": self.cfg.llm_max_tokens,
             "temperature": self.cfg.llm_temperature, "system": system,
             "messages": [{"role": "user", "content": user}]},
        )
        return "".join(b.get("text", "") for b in body.get("content", []))

    def _openai(self, system: str, user: str) -> str:
        base = "https://api.openai.com/v1/chat/completions"
        body = self._post(
            base,
            {"content-type": "application/json",
             "authorization": f"Bearer {self.cfg.llm_api_key}"},
            {"model": self.cfg.llm_model, "temperature": self.cfg.llm_temperature,
             "max_tokens": self.cfg.llm_max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}]},
        )
        return body["choices"][0]["message"]["content"]


def parse_json(text: str) -> dict | None:
    """Robustly pull the first JSON object out of a model reply."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
