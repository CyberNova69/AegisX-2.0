#!/usr/bin/env python3
"""
AegisX LLM Interface Unit Tests
=================================

Comprehensive test suite verifying the LLM interface abstraction layer.
Uses MockProvider to ensure tests do NOT require an API key or internet connection.

Usage:
    python -m unittest tests/test_llm.py -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.llm import (
    LLMClient,
    BaseLLMProvider,
    LLMConfig,
    LLMRequest,
    LLMResponse,
    TokenUsage,
    LLMError,
    LLMConfigurationError,
    LLMAuthenticationError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMResponseError,
    LLMProviderError,
)
from ai.llm.providers import MockProvider, APIProvider


class TestLLMInterface(unittest.TestCase):
    """Unit test suite for LLM abstraction layer."""

    def test_mock_provider_basic_generation(self):
        """MockProvider returns a valid normalized LLMResponse."""
        provider = MockProvider(default_response='{"status": "ok"}', default_model="mock-test-v1")
        req = LLMRequest(user_prompt="Hello AegisX", system_prompt="You are a SOC assistant.")
        resp = provider.generate(req)

        self.assertEqual(resp.provider, "mock")
        self.assertEqual(resp.model, "mock-test-v1")
        self.assertEqual(resp.content, '{"status": "ok"}')
        self.assertIsNotNone(resp.usage)
        self.assertGreater(resp.usage.total_tokens, 0)
        self.assertEqual(resp.structured_data, {"status": "ok"})

    def test_mock_provider_custom_responses(self):
        """MockProvider returns specific registered responses based on prompt keywords."""
        provider = MockProvider()
        provider.register_response("triage alert", '{"classification": "likely_malicious"}')

        req1 = LLMRequest(user_prompt="Please triage alert SOC-001")
        resp1 = provider.generate(req1)
        self.assertEqual(resp1.structured_data, {"classification": "likely_malicious"})

        req2 = LLMRequest(user_prompt="General question about DNS")
        resp2 = provider.generate(req2)
        self.assertNotEqual(resp2.content, '{"classification": "likely_malicious"}')

    def test_llm_client_orchestration(self):
        """LLMClient orchestrates provider calls seamlessly."""
        client = LLMClient.from_mock(default_response="System online.")
        resp = client.generate(user_prompt="Ping", system_prompt="System check.")

        self.assertEqual(resp.content, "System online.")
        self.assertEqual(resp.provider, "mock")

    def test_structured_json_parsing(self):
        """LLMClient successfully parses structured JSON responses."""
        valid_json = '{"classification": "benign", "severity": "low", "confidence": 0.9}'
        client = LLMClient.from_mock(default_response=valid_json)

        schema_spec = {"type": "object", "properties": {"classification": {"type": "string"}}}
        resp = client.generate(user_prompt="Classify activity", response_schema=schema_spec)

        self.assertIsNotNone(resp.structured_data)
        self.assertEqual(resp.structured_data["classification"], "benign")
        self.assertEqual(resp.structured_data["confidence"], 0.9)

    def test_structured_json_parsing_with_markdown_blocks(self):
        """LLMClient cleans markdown ```json block formatting automatically."""
        wrapped_json = "```json\n{\"classification\": \"suspicious\"}\n```"
        client = LLMClient.from_mock(default_response=wrapped_json)

        schema_spec = {"type": "object"}
        resp = client.generate(user_prompt="Analyze", response_schema=schema_spec)
        self.assertEqual(resp.structured_data, {"classification": "suspicious"})

    def test_invalid_json_response_raises_error(self):
        """LLMClient raises LLMResponseError when response is not valid JSON but schema requested."""
        client = LLMClient.from_mock(default_response="This is plain text, not JSON.")

        schema_spec = {"type": "object"}
        with self.assertRaises(LLMResponseError):
            client.generate(user_prompt="Analyze", response_schema=schema_spec)

    def test_missing_api_key_raises_auth_error(self):
        """APIProvider raises LLMAuthenticationError when API key is missing."""
        provider = APIProvider(api_key="")
        req = LLMRequest(user_prompt="Test")

        with self.assertRaises(LLMAuthenticationError):
            provider.generate(req)

    def test_secret_redaction(self):
        """Exception messages redact API keys and bearer tokens."""
        err_msg = "Failed request with sk-proj-1234567890abcdefghijklmnopqrstuvwxyz and Bearer secret_token_xyz"
        exc = LLMError(err_msg, provider="api")

        self.assertNotIn("sk-proj-1234567890abcdefghijklmnopqrstuvwxyz", str(exc))
        self.assertNotIn("secret_token_xyz", str(exc))
        self.assertIn("sk-***REDACTED***", str(exc))
        self.assertIn("***REDACTED***", str(exc))

    def test_invalid_config_validation(self):
        """LLMConfig validates parameter boundaries."""
        with self.assertRaises(LLMConfigurationError):
            LLMConfig(temperature=3.5).validate()

        with self.assertRaises(LLMConfigurationError):
            LLMConfig(max_tokens=-10).validate()

        with self.assertRaises(LLMConfigurationError):
            LLMConfig(timeout=0).validate()

    def test_config_loading_defaults(self):
        """LLMConfig loads valid defaults."""
        cfg = LLMConfig.load(PROJECT_ROOT)
        self.assertIsNotNone(cfg.provider_name)
        self.assertIsNotNone(cfg.model_name)
        self.assertGreater(cfg.max_tokens, 0)
        self.assertGreater(cfg.timeout, 0)

    def test_environment_variable_overrides(self):
        """Environment variables override config defaults."""
        old_provider = os.environ.get("LLM_PROVIDER")
        old_model = os.environ.get("LLM_MODEL")

        try:
            os.environ["LLM_PROVIDER"] = "mock"
            os.environ["LLM_MODEL"] = "env-custom-model"

            cfg = LLMConfig.load(PROJECT_ROOT)
            self.assertEqual(cfg.provider_name, "mock")
            self.assertEqual(cfg.model_name, "env-custom-model")
        finally:
            if old_provider:
                os.environ["LLM_PROVIDER"] = old_provider
            else:
                os.environ.pop("LLM_PROVIDER", None)

            if old_model:
                os.environ["LLM_MODEL"] = old_model
            else:
                os.environ.pop("LLM_MODEL", None)

    def test_simulated_error_raising(self):
        """MockProvider can simulate rate-limits or timeouts for exception testing."""
        provider = MockProvider(error_to_raise=LLMRateLimitError("Rate limit exceeded", provider="mock"))
        client = LLMClient(provider=provider)

        with self.assertRaises(LLMRateLimitError):
            client.generate("Test prompt")

    def test_provider_switching(self):
        """LLMClient supports switching providers seamlessly."""
        mock_provider = MockProvider(default_response="Mock answer")
        client = LLMClient(provider=mock_provider)

        r1 = client.generate("Question 1")
        self.assertEqual(r1.provider, "mock")
        self.assertEqual(r1.content, "Mock answer")


if __name__ == "__main__":
    unittest.main()
