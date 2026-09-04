"""
AegisX Base LLM Provider
=========================

Abstract interface defining the contract for all LLM providers (Mock, API, Local).
Ensures higher-level agents interact with a consistent, provider-agnostic interface.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any

from ai.llm.schemas import LLMRequest, LLMResponse
from ai.llm.exceptions import LLMError

class BaseLLMProvider(ABC):
    """Abstract base class for all AegisX LLM providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider type name (e.g. 'mock', 'api', 'local')."""
        pass

    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Execute an LLM generation request and return a normalized LLMResponse.
        
        Args:
            request: Normalized LLMRequest dataclass.
            
        Returns:
            LLMResponse: Normalized response with content, metadata, and usage.
            
        Raises:
            LLMError: On configuration, network, timeout, authentication, or provider error.
        """
        pass

    def sanitize_log_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Utility method to sanitize sensitive items prior to logging."""
        sanitized = {}
        for k, v in data.items():
            if any(secret_key in k.lower() for secret_key in ["key", "token", "auth", "password", "secret"]):
                sanitized[k] = "***REDACTED***"
            elif isinstance(v, dict):
                sanitized[k] = self.sanitize_log_dict(v)
            else:
                sanitized[k] = v
        return sanitized
