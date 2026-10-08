"""MCP adapter: put a memgate boundary in front of an MCP ClientSession.

    async with ClientSession(read, write) as raw:
        await raw.initialize()
        session = GatedClientSession(raw, boundary, session_id="s1")
        result = await session.call_tool("send_email", {"to": ..., "bcc": ...})

Blocked calls return a `CallToolResult` with `isError=True` and the policy
reason as text (`is_error` in mcp 2.x), so an MCP host relays it to the model like any tool error.
Everything other than `call_tool` is delegated to the wrapped session.
"""

from __future__ import annotations

from typing import Any

from mcp.types import CallToolResult, TextContent

from ..boundary import ToolBoundary


def _text(result: Any) -> str:
    parts = []
    for c in getattr(result, "content", None) or []:
        t = getattr(c, "text", None)
        parts.append(t if t is not None else f"[{getattr(c, 'type', 'content')}]")
    sc = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)  # mcp 2.x / 1.x
    if sc:
        parts.append(str(sc))
    return "\n".join(parts)


class GatedClientSession:
    def __init__(self, inner: Any, boundary: ToolBoundary, session_id: str) -> None:
        self._inner = inner
        self.boundary = boundary
        self.session_id = session_id

    def __getattr__(self, item: str) -> Any:
        return getattr(self._inner, item)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None, *a: Any, **kw: Any):
        g = self.boundary.gate(name, arguments or {}, self.session_id)
        if not g.execute:
            res = self.boundary.finish(g)
            return CallToolResult(content=[TextContent(type="text", text=res.output)], isError=True)
        result = await self._inner.call_tool(name, arguments, *a, **kw)
        self.boundary.finish(g, _text(result))
        return result
