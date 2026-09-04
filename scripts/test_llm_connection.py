#!/usr/bin/env python3
"""
AegisX LLM Manual Connection Smoke Test
=========================================

Optional CLI utility to verify external API provider connectivity.
Loads credentials securely from .env or environment variables.

Usage:
    python scripts/test_llm_connection.py
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.llm import LLMClient, LLMConfig, LLMAuthenticationError, LLMError

def main():
    print("==================================================")
    print("  AegisX LLM Interface Connection Test")
    print("==================================================")

    config = LLMConfig.load(PROJECT_ROOT)

    key_prefix = (config.api_key[:4] + "...") if config.api_key else "NONE"
    print(f"  Configured Provider: {config.provider_name}")
    print(f"  Configured Model:    {config.model_name}")
    print(f"  Base URL:            {config.api_base_url}")
    print(f"  API Key Present:     {'YES' if config.api_key else 'NO'} (Prefix: {key_prefix})")
    print("==================================================\n")

    if config.provider_name == "api" and not config.api_key:
        print("[NOTICE] No API key detected in environment or .env file.")
        print("To test external API connectivity:")
        print("  1. Copy .env.example to .env")
        print("  2. Set LLM_API_KEY=your_actual_key")
        print("  3. Set LLM_PROVIDER=api in .env or model.yaml\n")
        print("Running fallback smoke test using MockProvider instead...")
        client = LLMClient.from_mock()
    else:
        client = LLMClient.from_config(config)

    print("Sending test request to provider...")
    try:
        response = client.generate(
            system_prompt="You are a SOC assistant.",
            user_prompt="Say 'AegisX LLM Interface Operational' and state your model name.",
            max_tokens=50,
        )
        print("\n[SUCCESS] Response received:")
        print(f"  Provider:       {response.provider}")
        print(f"  Model:          {response.model}")
        print(f"  Latency:        {response.latency_ms:.1f} ms")
        print(f"  Tokens Used:    {response.usage.total_tokens}")
        safe_content = response.content.strip().encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8')
        print(f"  Response Text:  {safe_content}\n")
        return 0

    except LLMAuthenticationError as e:
        print(f"\n[AUTHENTICATION ERROR] {e}")
        print("Check your API key in .env or environment variables.")
        return 1
    except LLMError as e:
        print(f"\n[ERROR] Request failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
