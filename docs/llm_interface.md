# AegisX LLM Interface (Phase 2)

## 1. Purpose

The AegisX LLM Interface provides a **provider-independent abstraction layer** in `ai/llm/` that decouples all future AI agent modules (Triage Agent, Investigation Agent, Threat Intel Agent, RAG, Fine-tuning) from specific LLM vendors, frameworks, or model implementations.

---

## 2. Architecture

```
                 Agent / SOC Component
                          │
                          ▼
                      LLMClient
                          │
                          ▼
               BaseLLMProvider (Interface)
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
     MockProvider    APIProvider    Future LocalProvider
     (Offline/CI)    (OpenAI/HTTP)   (vLLM / PyTorch)
```

### Key Modules

- `ai/llm/client.py`: High-level `LLMClient` orchestrator exposing `generate()` and handling structured output parsing.
- `ai/llm/base.py`: Abstract `BaseLLMProvider` contract.
- `ai/llm/providers/mock.py`: `MockProvider` for offline testing, CI automation, and deterministic unit tests.
- `ai/llm/providers/api.py`: `APIProvider` connecting to external HTTP/REST endpoints with retry backoff and secret protection.
- `ai/llm/schemas.py`: Data models (`LLMRequest`, `LLMResponse`, `TokenUsage`).
- `ai/llm/config.py`: Configuration loader parsing `configs/model.yaml` and `.env` environment variables.
- `ai/llm/exceptions.py`: Custom exception hierarchy (`LLMError`, `LLMAuthenticationError`, `LLMTimeoutError`, etc.) with automatic secret redaction.

---

## 3. Quick Start

### Basic Usage with Mock Provider (Default)

```python
from ai.llm import LLMClient

# Initialize client using MockProvider
client = LLMClient.from_mock()

response = client.generate(
    system_prompt="You are an expert SOC analyst.",
    user_prompt="Analyze this PowerShell execution event."
)

print(f"Provider: {response.provider}")
print(f"Model: {response.model}")
print(f"Content: {response.content}")
```

### Requesting Structured JSON Output

```python
from ai.llm import LLMClient

client = LLMClient.from_mock(
    default_response='{"classification": "likely_malicious", "confidence": 0.85}'
)

response = client.generate(
    user_prompt="Classify alert SOC-000042",
    response_schema={"type": "object"}
)

print(response.structured_data["classification"])  # -> 'likely_malicious'
```

---

## 4. Configuration & Credentials

### Non-Secret Settings (`configs/model.yaml`)

```yaml
provider:
  name: "mock"                # 'mock' or 'api'

model:
  name: "mock-soc-analyst-v1"

generation:
  temperature: 0.2
  max_tokens: 1024
  timeout: 30.0
  max_retries: 3
```

### Credentials (`.env`)

Secrets must **NEVER** be committed to Git. Copy `.env.example` to `.env`:

```bash
LLM_API_KEY=your_actual_api_key_here
LLM_PROVIDER=api
```

`.env` is automatically ignored in `.gitignore`.

---

## 5. Security & Secret Redaction

- Error messages automatically redact API key patterns (`sk-...`, `Bearer ...`).
- Loggers mask authorization headers.
- Unit tests use `MockProvider` and do **NOT** require an API key or internet connection.

---

## 6. How to Switch Providers

Switching providers requires **zero changes** to higher-level agent code.

### Option A: Environment Variable
```bash
export LLM_PROVIDER=api
export LLM_API_KEY=your_key
```

### Option B: `configs/model.yaml`
```yaml
provider:
  name: "api"
```

---

## 7. Future Local & Fine-Tuned Model Path

In Phase 10, when fine-tuning on dedicated GPU hardware is performed, a `LocalProvider` will be added to `ai/llm/providers/local.py` wrapping the local PyTorch / vLLM engine. Because agents depend exclusively on `LLMClient`, switching from API to Local Fine-Tuned model will require updating only the configuration.
