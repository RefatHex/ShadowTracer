"""OpenAI-compatible chat client for the investigation agent (default: local Ollama gemma4:e4b).

One endpoint (base_url, model, optional api_key). The api_key is sent only as a bearer header and is
NEVER logged or returned. A down/slow endpoint raises LLMUnavailable so the caller can still show the
evidence pack and never 5xx.
"""
from __future__ import annotations

import httpx


class LLMUnavailable(RuntimeError):
    """The LLM endpoint could not be reached or timed out - advisory feature, degrade gracefully."""


class LLMClient:
    def __init__(self, base_url: str, model: str, api_key: str | None,
                 timeout_seconds: int, num_ctx: int, max_tokens: int):
        self._base = base_url.rstrip("/")
        self._model = model
        self._key = api_key
        self._timeout = timeout_seconds
        self._num_ctx = num_ctx
        self._max_tokens = max_tokens

    @property
    def model(self) -> str:
        return self._model

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._key:                       # bearer only; never logged
            h["Authorization"] = f"Bearer {self._key}"
        return h

    def health(self) -> bool:
        try:
            r = httpx.get(f"{self._base}/models", headers=self._headers(), timeout=5)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             max_tokens: int | None = None) -> dict:
        """-> {"content": str, "tool_calls": list|None, "usage": {...}}. Raises LLMUnavailable."""
        body = {
            "model": self._model,
            "messages": messages,
            "temperature": 0.1,                         # near-deterministic for a small model
            "max_tokens": max_tokens or self._max_tokens,
            # Ollama honours num_ctx via options on its native path; harmless to the OpenAI shim.
            "options": {"num_ctx": self._num_ctx},
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        try:
            r = httpx.post(f"{self._base}/chat/completions", json=body,
                           headers=self._headers(), timeout=self._timeout)
            r.raise_for_status()
        except httpx.HTTPError as e:                     # never leak the key in the message
            raise LLMUnavailable(f"LLM endpoint error: {type(e).__name__}") from None
        data = r.json()
        msg = (data.get("choices") or [{}])[0].get("message", {})
        return {"content": msg.get("content") or "", "tool_calls": msg.get("tool_calls"),
                "usage": data.get("usage") or {}}
