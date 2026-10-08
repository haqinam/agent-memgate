"""List model ids your API key can use, optionally filtered by substrings.

    uv run --extra all python eval/list_models.py openai luna gpt-6
    uv run --extra all python eval/list_models.py anthropic
"""

from __future__ import annotations

import sys


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("openai", "anthropic", "openweights"):
        sys.exit(__doc__)
    provider, terms = argv[0], [t.lower() for t in argv[1:]]
    if provider == "anthropic":
        import anthropic
        ids = sorted(m.id for m in anthropic.Anthropic().models.list())
    else:
        import os

        import openai
        kw = {}
        if provider == "openweights":
            kw = {"base_url": os.environ["OPENWEIGHTS_BASE_URL"],
                  "api_key": os.environ.get("OPENWEIGHTS_API_KEY", "not-needed")}
        ids = sorted(m.id for m in openai.OpenAI(**kw).models.list())
    hits = [i for i in ids if any(t in i.lower() for t in terms)] if terms else ids
    sys.stdout.write("\n".join(hits or ["(no match; all models:)", *ids]) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
