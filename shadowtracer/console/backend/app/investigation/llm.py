"""Chat client for the investigation agent. Default: local Ollama (gemma4:e4b) over its NATIVE
`/api/chat` endpoint, because that is the only Ollama endpoint that honours a per-request `num_ctx`
(the OpenAI-compatible `/v1` shim silently ignores it and loads the model at its 4096 default - which
would make the prompt-truncation guard unsound). An external OpenAI-compatible provider is still
supported: give it a base_url ending in `/v1` and the client speaks the OpenAI schema instead.

One endpoint (base_url, model, optional api_key). The api_key is sent only as a bearer header and is
NEVER logged or returned. A down/slow endpoint raises LLMUnavailable so the caller can still show the
evidence pack and never 5xx.
"""
from __future__ import annotations

import httpx


class LLMUnavailable(RuntimeError):
    """The LLM endpoint could not be reached or timed out - advisory feature, degrade gracefully."""


class LLMPromptTruncated(RuntimeError):
    """The evidence prompt exceeded the model's context window and Ollama truncated it - fail the
    investigation rather than answer on partial evidence."""


class LLMClient:
    def __init__(self, base_url: str, model: str, api_key: str | None,
                 timeout_seconds: int, num_ctx: int, max_tokens: int, keep_alive: str = "30m"):
        self._base = base_url.rstrip("/")
        self._openai = self._base.endswith("/v1")   # /v1 -> OpenAI schema (external); else Ollama native
        self._model = model
        self._key = api_key
        self._timeout = timeout_seconds
        self._num_ctx = num_ctx
        self._max_tokens = max_tokens
        self._keep_alive = keep_alive               # keep the model resident between calls (native only)

    @property
    def model(self) -> str:
        return self._model

    @property
    def num_ctx(self) -> int:
        return self._num_ctx

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._key:                       # bearer only; never logged
            h["Authorization"] = f"Bearer {self._key}"
        return h

    def health(self) -> bool:
        path = "/models" if self._openai else "/api/tags"
        try:
            r = httpx.get(f"{self._base}{path}", headers=self._headers(), timeout=5)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def warmup(self) -> bool:
        """Best-effort: load the model into VRAM with the SAME options real calls use (num_ctx,
        keep_alive), so the first investigation doesn't pay the cold load_duration. False if down."""
        try:
            self.chat([{"role": "user", "content": "ok"}], max_tokens=1)
            return True
        except LLMUnavailable:
            return False

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             max_tokens: int | None = None) -> dict:
        """-> {"content": str, "tool_calls": list|None, "usage": {prompt_tokens,...}}. Raises LLMUnavailable.

        usage["prompt_tokens"] == Ollama's prompt_eval_count, used by the agent's truncation guard."""
        mt = max_tokens or self._max_tokens
        if self._openai:
            url = f"{self._base}/chat/completions"
            body: dict = {"model": self._model, "messages": messages, "temperature": 0.1,
                          "max_tokens": mt, "options": {"num_ctx": self._num_ctx}}  # options: no-op on /v1
            if tools:
                body["tools"] = tools
                body["tool_choice"] = "auto"
        else:                                           # Ollama native - honours num_ctx per request
            url = f"{self._base}/api/chat"
            # IDENTICAL options on every local call + keep_alive, so Ollama never reloads the model
            # between the two passes of one investigation (a changed num_ctx/options forces a reload).
            body = {"model": self._model, "messages": messages, "stream": False,
                    "keep_alive": self._keep_alive,
                    "options": {"temperature": 0.1, "num_ctx": self._num_ctx, "num_predict": mt}}
            if tools:
                body["tools"] = tools
        try:
            r = httpx.post(url, json=body, headers=self._headers(), timeout=self._timeout)
            r.raise_for_status()
        except httpx.HTTPError as e:                     # never leak the key in the message
            raise LLMUnavailable(f"LLM endpoint error: {type(e).__name__}") from None
        data = r.json()
        if self._openai:
            msg = (data.get("choices") or [{}])[0].get("message", {})
            return {"content": msg.get("content") or "", "tool_calls": msg.get("tool_calls"),
                    "usage": data.get("usage") or {}}
        msg = data.get("message", {})                    # native schema
        pe, ev = int(data.get("prompt_eval_count", 0) or 0), int(data.get("eval_count", 0) or 0)
        return {"content": msg.get("content") or "", "tool_calls": msg.get("tool_calls"),
                "usage": {"prompt_tokens": pe, "completion_tokens": ev, "total_tokens": pe + ev}}
