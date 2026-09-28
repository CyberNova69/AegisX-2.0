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

DEFAULT_MOCK_RESPONSE = (
    '{"classification": "suspicious", "severity": "medium", "confidence": 0.85, '
    '"investigation_required": true, '
    '"summary": "Mock security analysis completed. Suspicious activity detected requiring investigation.", '
    '"findings": [{"finding": "Suspicious activity detected in mock analysis", "evidence_ids": ["EVT-000001"]}], '
    '"evidence_ids": ["EVT-000001"], '
    '"recommended_actions": [{"action": "flag_for_review", "priority": "medium", "rationale": "Mock analysis flagged suspicious patterns"}]}'
)


class MockProvider(BaseLLMProvider):
    """
    Mock LLM provider returning controlled, deterministic responses for testing.
    """

    def __init__(
        self,
        default_response: str = DEFAULT_MOCK_RESPONSE,
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
        content = None
        for sub, resp in self.custom_responses.items():
            if sub in request.user_prompt:
                content = resp
                break

        if content is None:
            if self.default_response == DEFAULT_MOCK_RESPONSE:
                prompt = request.user_prompt or ""
                import re
                found_evts = re.findall(r"EVT-\d+", prompt)
                first_evt = found_evts[0] if found_evts else "EVT-000001"

                if "FINAL INVESTIGATION SYNTHESIS" in prompt or "REQUIRED FINAL REPORT JSON FORMAT" in prompt:
                    content = json.dumps({
                        "status": "completed",
                        "conclusion": "suspicious",
                        "severity": "medium",
                        "confidence": 0.85,
                        "findings": [{
                            "finding_id": "FIND-001",
                            "title": "Suspicious Activity Confirmed",
                            "description": "Mock investigation identified suspicious activity.",
                            "evidence_ids": [first_evt],
                            "confidence": 0.85,
                        }],
                        "recommended_actions": [{
                            "action": "flag_for_review",
                            "priority": "medium",
                            "rationale": "Review activity context with SOC analyst.",
                        }],
                        "limitations": "Mock provider offline analysis.",
                    })
                elif "INVESTIGATION STEP" in prompt or "AVAILABLE READ-ONLY TOOLS" in prompt:
                    content = json.dumps({
                        "action": "finish",
                        "stop_reason": "Sufficient evidence collected to confirm alert validity.",
                    })
                elif "FINAL THREAT INTELLIGENCE SYNTHESIS" in prompt or "AUTHORIZED EVIDENCE IDS YOU MAY CITE" in prompt:
                    content = json.dumps({
                        "status": "completed",
                        "confidence": 0.85,
                        "summary": "Mock threat intelligence enrichment completed.",
                        "findings": [{
                            "finding_id": "TI-001",
                            "title": "Threat Intelligence Finding",
                            "description": "Indicators matched threat intelligence criteria.",
                            "category": "reputation",
                            "evidence_ids": [first_evt],
                            "confidence": 0.85,
                        }],
                        "indicators_analyzed": [],
                        "mitre_techniques": [],
                        "evidence_ids": [first_evt],
                        "recommendations": ["flag_for_review"],
                    })
                elif "THREAT INTELLIGENCE ENRICHMENT STEP" in prompt or "AVAILABLE ACTIONS" in prompt:
                    content = json.dumps({
                        "action": "finish",
                        "stop_reason": "Sufficient threat intelligence context available.",
                    })
                else:
                    content = json.dumps({
                        "classification": "suspicious",
                        "severity": "medium",
                        "confidence": 0.85,
                        "investigation_required": True,
                        "summary": "Mock security analysis completed. Suspicious activity detected requiring investigation.",
                        "findings": [{
                            "finding": "Suspicious activity detected in mock analysis",
                            "evidence_ids": [first_evt],
                        }],
                        "evidence_ids": [first_evt],
                        "recommended_actions": [{
                            "action": "flag_for_review",
                            "priority": "medium",
                            "rationale": "Mock analysis flagged suspicious patterns",
                        }],
                    })
            else:
                content = self.default_response

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
