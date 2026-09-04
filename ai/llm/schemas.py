"""
AegisX LLM Interface Schemas
=============================

Standard data structures for requests, responses, token accounting,
and structured output specifications.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

@dataclass
class TokenUsage:
    """Token consumption accounting."""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }

@dataclass
class LLMRequest:
    """Normalized request sent to an LLM provider."""
    user_prompt: str
    system_prompt: Optional[str] = None
    model: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 1024
    timeout: float = 30.0
    response_schema: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class LLMResponse:
    """Normalized response returned by an LLM provider."""
    content: str
    model: str
    provider: str
    usage: TokenUsage = field(default_factory=TokenUsage)
    finish_reason: str = "stop"
    latency_ms: float = 0.0
    structured_data: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider,
            "usage": self.usage.to_dict(),
            "finish_reason": self.finish_reason,
            "latency_ms": self.latency_ms,
            "structured_data": self.structured_data,
            "metadata": self.metadata,
        }
