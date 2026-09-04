"""
AegisX LLM Module Package
==========================

Exports the high-level LLMClient, base provider, configuration,
schemas, and exception hierarchy.
"""

from ai.llm.base import BaseLLMProvider
from ai.llm.client import LLMClient
from ai.llm.config import LLMConfig
from ai.llm.exceptions import (
    LLMError,
    LLMConfigurationError,
    LLMAuthenticationError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMResponseError,
    LLMProviderError,
)
from ai.llm.schemas import LLMRequest, LLMResponse, TokenUsage

__all__ = [
    "LLMClient",
    "BaseLLMProvider",
    "LLMConfig",
    "LLMRequest",
    "LLMResponse",
    "TokenUsage",
    "LLMError",
    "LLMConfigurationError",
    "LLMAuthenticationError",
    "LLMTimeoutError",
    "LLMRateLimitError",
    "LLMResponseError",
    "LLMProviderError",
]
