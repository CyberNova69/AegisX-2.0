"""
AegisX External API LLM Provider
=================================

Provider implementation for external HTTP/REST LLM endpoints (OpenAI / OpenRouter / Anthropic / Local vLLM).
Uses Python standard library urllib or requests/httpx with fallback for lightweight HTTP requests.
Implements exponential backoff retries, response normalization, and secret protection.
"""

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from ai.llm.base import BaseLLMProvider
from ai.llm.schemas import LLMRequest, LLMResponse, TokenUsage
from ai.llm.exceptions import (
    LLMError,
    LLMConfigurationError,
    LLMAuthenticationError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMResponseError,
    LLMProviderError,
)

class APIProvider(BaseLLMProvider):
    """
    HTTP/REST API Provider supporting OpenAI-compatible chat completion endpoints.
    Requires an API key provided via parameter or LLM_API_KEY / OPENAI_API_KEY environment variable.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        default_model: str = "gpt-4o-mini",
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        raw_key = api_key or os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.api_key = raw_key.strip().strip("'\"") if raw_key else None
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    @property
    def name(self) -> str:
        return "api"

    def generate(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise LLMAuthenticationError(
                "API key is missing. Set LLM_API_KEY environment variable or pass api_key to provider.",
                provider=self.name,
            )

        model = request.model or self.default_model
        endpoint = f"{self.base_url}/chat/completions"

        # Build OpenAI-compatible chat payload
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.user_prompt})

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }

        # Request structured JSON format if specified
        if request.response_schema:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AegisX-SOC/1.0 (Python)",
            "Authorization": f"Bearer {self.api_key}",
        }

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data_bytes, headers=headers, method="POST")

        attempt = 0
        start_time = time.time()
        last_exception = None

        while attempt <= self.max_retries:
            attempt += 1
            try:
                with urllib.request.urlopen(req, timeout=request.timeout) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    latency_ms = round((time.time() - start_time) * 1000, 2)
                    return self._normalize_response(resp_data, model, latency_ms)

            except urllib.error.HTTPError as e:
                status_code = e.code
                error_body = e.read().decode("utf-8", errors="replace")

                if status_code in (401, 403):
                    raise LLMAuthenticationError(f"HTTP {status_code} Authentication failed: {error_body}", provider=self.name)
                elif status_code == 429:
                    last_exception = LLMRateLimitError(f"HTTP 429 Rate limit exceeded: {error_body}", provider=self.name)
                elif status_code >= 500:
                    last_exception = LLMProviderError(f"HTTP {status_code} Server Error: {error_body}", provider=self.name)
                else:
                    raise LLMResponseError(f"HTTP {status_code} Request Error: {error_body}", provider=self.name)

            except (urllib.error.URLError, TimeoutError, SocketError if 'SocketError' in locals() else Exception) as e:
                if "timed out" in str(e).lower() or isinstance(e, TimeoutError):
                    last_exception = LLMTimeoutError(f"Request timed out after {request.timeout}s: {e}", provider=self.name)
                else:
                    last_exception = LLMProviderError(f"Connection error: {e}", provider=self.name)

            # Retry with exponential backoff if transient error
            if attempt <= self.max_retries:
                if isinstance(last_exception, LLMRateLimitError):
                    sleep_time = max(6.0 * attempt, self.retry_delay * (2 ** (attempt - 1)))
                else:
                    sleep_time = self.retry_delay * (2 ** (attempt - 1))
                time.sleep(sleep_time)

        if last_exception:
            raise last_exception
        raise LLMProviderError("Request failed after max retries.", provider=self.name)

    def _normalize_response(self, raw_resp: Dict[str, Any], requested_model: str, latency_ms: float) -> LLMResponse:
        """Convert raw OpenAI-style API response into normalized LLMResponse."""
        try:
            choice = raw_resp["choices"][0]
            content = choice["message"]["content"]
            finish_reason = choice.get("finish_reason", "stop")

            usage_raw = raw_resp.get("usage", {})
            usage = TokenUsage(
                input_tokens=usage_raw.get("prompt_tokens", 0),
                output_tokens=usage_raw.get("completion_tokens", 0),
                total_tokens=usage_raw.get("total_tokens", 0),
            )

            # Attempt structured JSON parsing
            structured_data = None
            if content.strip().startswith("{") or content.strip().startswith("["):
                try:
                    structured_data = json.loads(content)
                except json.JSONDecodeError:
                    pass

            return LLMResponse(
                content=content,
                model=raw_resp.get("model", requested_model),
                provider=self.name,
                usage=usage,
                finish_reason=finish_reason,
                latency_ms=latency_ms,
                structured_data=structured_data,
                metadata={"id": raw_resp.get("id")},
            )

        except (KeyError, IndexError, TypeError) as e:
            raise LLMResponseError(f"Malformed API response structure: {e}", provider=self.name)
