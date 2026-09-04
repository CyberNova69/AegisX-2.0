"""
AegisX Mock LLM Provider
=========================

Deterministic LLM provider for unit testing, offline development,
and CI/CD automation without API costs or internet dependency.
"""

import json
import time
from typing import Any, Dict, Optional, Callable

from ai.llm.base import BaseLLMProvider
from ai.llm.schemas import LLMRequest, LLMResponse, TokenUsage
from ai.llm.exceptions import (
    LLMError,
    LLMTimeoutError,
    LLMAuthenticationError,
    LLMRateLimitError,
    LLMProviderError,
)

class MockProvider(BaseLLMProvider):
    """
    Mock LLM provider returning controlled, deterministic responses for testing.
    """

    def __init__(
        self,
        default_response: str = '{"classification": "suspicious", "confidence": 0.85, "rationale": "Mock security analysis completed."}',
        default_model: str = "mock-soc-analyst-v1",
        simulated_latency_ms: float = 5.0,
        error_to_raise: Optional[Exception] = None,
    ):
        self.default_response = default_response
        self.default_model = default_model
        self.simulated_latency_ms = simulated_latency_ms
        self.error_to_raise = error_to_raise
        self.custom_responses: Dict[str, str] = {}
        self.call_history: list[LLMRequest] = []

    @property
    def name(self) -> str:
        return "mock"

    def register_response(self, user_prompt_substring: str, response_content: str):
        """Register a specific mock response when user prompt contains a substring."""
        self.custom_responses[user_prompt_substring] = response_content

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.call_history.append(request)

        if self.error_to_raise:
            raise self.error_to_raise

        if self.simulated_latency_ms > 0:
            time.sleep(self.simulated_latency_ms / 1000.0)

        # Check for matching custom responses
        content = self.default_response
        for sub, resp in self.custom_responses.items():
            if sub in request.user_prompt:
                content = resp
                break

        # If request has structured response schema requirement and no custom matches, check formatting
        structured_data = None
        if request.response_schema or content.strip().startswith("{"):
            try:
                structured_data = json.loads(content)
            except json.JSONDecodeError:
                pass

        # Calculate mock usage metrics
        input_tokens = len((request.system_prompt or "") + request.user_prompt) // 4
        output_tokens = len(content) // 4
        usage = TokenUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
        )

        model_name = request.model or self.default_model

        return LLMResponse(
            content=content,
            model=model_name,
            provider=self.name,
            usage=usage,
            finish_reason="stop",
            latency_ms=self.simulated_latency_ms,
            structured_data=structured_data,
            metadata={"mock_call_count": len(self.call_history)},
        )
