"""Provider registry. To add a provider: implement `complete(messages, tools)`
(see base.py), then add it to PROVIDERS and ENV_KEYS below."""

from __future__ import annotations

import os

ENV_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY"}
NAMES = ["mock", "anthropic", "openai", "gemini"]


def available() -> list[str]:
    """`mock` always; real providers whose API-key env var is set."""
    return ["mock"] + [p for p, k in ENV_KEYS.items() if os.environ.get(k)]


def make_provider(name: str, scenario: dict, model: str | None = None):
    if name == "mock":
        from .mock import MockProvider
        return MockProvider(scenario)
    if name == "anthropic":
        from .anthropic_ import AnthropicProvider
        return AnthropicProvider(model)
    if name == "openai":
        from .openai_ import OpenAIProvider
        return OpenAIProvider(model)
    if name == "gemini":
        from .gemini_ import GeminiProvider
        return GeminiProvider(model)
    raise ValueError(f"unknown provider {name!r}; choose from {NAMES}")
