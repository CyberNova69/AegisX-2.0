"""
AegisX LLM Interface Exceptions
================================

Custom exception hierarchy for the AegisX LLM interface layer.
Provides clean error classification and secret redaction in error messages.
"""

class LLMError(Exception):
    """Base exception class for all AegisX LLM interface errors."""
    def __init__(self, message: str, provider: str = "unknown", details: dict | None = None):
        self.message = message
        self.provider = provider
        self.details = details or {}
        super().__init__(self._sanitize(f"[{self.provider}] {self.message}"))

    @staticmethod
    def _sanitize(text: str) -> str:
        """Sanitize error messages to prevent accidental key leakage."""
        import re
        # Redact patterns like sk-..., bearer tokens, key=...
        text = re.sub(r"(sk-[A-Za-z0-9_-]+)", "sk-***REDACTED***", text)
        text = re.sub(r"(Bearer\s+)[A-Za-z0-9_.\-]+", r"\1***REDACTED***", text, flags=re.IGNORECASE)
        text = re.sub(r"(key=)[A-Za-z0-9_.\-]+", r"\1***REDACTED***", text, flags=re.IGNORECASE)
        return text

class LLMConfigurationError(LLMError):
    """Raised when configuration parameters or environment variables are invalid or missing."""
    pass

class LLMAuthenticationError(LLMError):
    """Raised when API key or authentication header is invalid (e.g. HTTP 401/403)."""
    pass

class LLMTimeoutError(LLMError):
    """Raised when a request exceeds the configured network timeout limit."""
    pass

class LLMRateLimitError(LLMError):
    """Raised when provider rate limits are exceeded (e.g. HTTP 429)."""
    pass

class LLMResponseError(LLMError):
    """Raised when the provider returns a malformed response or invalid JSON."""
    pass

class LLMProviderError(LLMError):
    """Raised when the provider returns a 5xx server-side error or unexpected failure."""
    pass
