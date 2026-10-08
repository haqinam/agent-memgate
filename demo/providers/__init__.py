"""Provider registry. To add a provider: implement `complete(messages, tools)`
(see base.py), then add it to make_provider and ENV_KEYS below."""

from __future__ import annotations

import os

ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openweights": "OPENWEIGHTS_BASE_URL",  # any OpenAI-compatible server: Ollama, vLLM, llama.cpp, ...
}
NAMES = ["mock", *ENV_KEYS]
_EXTRA = {"anthropic": "anthropic", "openai": "openai", "gemini": "gemini", "openweights": "openai"}


def available() -> list[str]:
    """`mock` always; real providers whose env var is set."""
    return ["mock"] + [p for p, k in ENV_KEYS.items() if os.environ.get(k)]


def make_provider(name: str, scenario: dict, model: str | None = None):
    try:
        if name == "mock":
            from .mock import MockProvider
            return MockProvider(scenario)
        if name == "anthropic":
            from .anthropic_ import AnthropicProvider
            return AnthropicProvider(model)
        if name == "openai":
            from .openai_ import OpenAIProvider
            return OpenAIProvider(model)
        if name == "openweights":
            from .openai_ import OpenWeightsProvider
            return OpenWeightsProvider(model)
        if name == "gemini":
            from .gemini_ import GeminiProvider
            return GeminiProvider(model)
    except ImportError as e:
        raise SystemExit(
            f"The {name!r} provider needs its SDK ({e.name}). Install it with:\n"
            f"  uv sync --extra {_EXTRA[name]}     (or: pip install -e '.[{_EXTRA[name]}]')"
        ) from None
    raise ValueError(f"unknown provider {name!r}; choose from {NAMES}")
