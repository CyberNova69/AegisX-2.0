"""
AegisX High-Level LLM Client
=============================

Primary entrypoint for all future AegisX agent modules.
Decouples agent logic from specific LLM providers and models.
Enforces structured output validation, logging, and error mapping.
"""

import json
import logging
from typing import Any, Dict, Optional, Union

from ai.llm.base import BaseLLMProvider
from ai.llm.config import LLMConfig
from ai.llm.exceptions import LLMError, LLMResponseError
from ai.llm.providers.mock import MockProvider
from ai.llm.providers.api import APIProvider
from ai.llm.schemas import LLMRequest, LLMResponse

logger = logging.getLogger("AegisX.LLM")

class LLMClient:
    """
    Provider-independent LLM client orchestrator.
    """

    def __init__(self, provider: Optional[BaseLLMProvider] = None, config: Optional[LLMConfig] = None):
        if provider:
            self.provider = provider
            self.config = config or LLMConfig(provider_name=provider.name)
        else:
            self.config = config or LLMConfig.load()
            self.provider = self._create_provider_from_config(self.config)

    @classmethod
    def from_mock(cls, default_response: Optional[str] = None) -> "LLMClient":
        """Factory helper to instantiate an LLMClient backed by MockProvider."""
        kwargs = {}
        if default_response:
            kwargs["default_response"] = default_response
        provider = MockProvider(**kwargs)
        return cls(provider=provider)

    @classmethod
    def from_config(cls, config: LLMConfig) -> "LLMClient":
        """Factory helper to instantiate an LLMClient from an explicit LLMConfig."""
        return cls(config=config)

    def generate(
        self,
        user_prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        response_schema: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LLMResponse:
        """
        Generate a completion using the configured provider.
        """
        req = LLMRequest(
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            model=model or self.config.model_name,
            temperature=temperature if temperature is not None else self.config.temperature,
            max_tokens=max_tokens if max_tokens is not None else self.config.max_tokens,
            timeout=timeout if timeout is not None else self.config.timeout,
            response_schema=response_schema,
            metadata=metadata or {},
        )

        logger.debug(f"LLM Request [{self.provider.name}]: model={req.model}")

        try:
            response = self.provider.generate(req)
        except LLMError as e:
            logger.error(f"LLM Failure [{self.provider.name}]: {e}")
            raise

        # Enforce structured output parsing if schema requested
        if response_schema:
            if not response.structured_data:
                # Attempt manual JSON extraction/parsing
                try:
                    cleaned_content = self._extract_json_substring(response.content)
                    response.structured_data = json.loads(cleaned_content)
                except (json.JSONDecodeError, ValueError) as e:
                    raise LLMResponseError(
                        f"Failed to parse structured JSON from model response: {e}. Raw content: {response.content[:100]}...",
                        provider=self.provider.name,
                    )

        logger.debug(f"LLM Response [{self.provider.name}]: latency={response.latency_ms}ms, tokens={response.usage.total_tokens}")
        return response

    @staticmethod
    def _create_provider_from_config(config: LLMConfig) -> BaseLLMProvider:
        """Instantiate appropriate provider adapter based on config."""
        name = config.provider_name.lower()
        if name == "mock":
            return MockProvider(default_model=config.model_name)
        elif name in ("api", "openai", "openrouter"):
            return APIProvider(
                api_key=config.api_key,
                base_url=config.api_base_url,
                default_model=config.model_name,
                max_retries=config.max_retries,
                retry_delay=config.retry_delay,
            )
        else:
            raise LLMError(f"Unsupported provider: '{name}'. Supported providers: 'mock', 'api'.", provider="client")

    @staticmethod
    def _extract_json_substring(text: str) -> str:
        """Extract JSON substring if wrapped in markdown block or whitespace."""
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        # Find first '{' and last '}'
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start : end + 1]
        return text
