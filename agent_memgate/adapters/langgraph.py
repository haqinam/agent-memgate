"""LangGraph / LangChain adapter.

    from agent_memgate.adapters.langgraph import gate_tools, memory_tools
    tools = gate_tools([web_fetch, send_email], boundary, session=lambda: thread_id)
    tools += memory_tools(store, boundary, session=lambda: thread_id)
    graph = create_react_agent(model, tools, prompt=lambda s: base + boundary.inject_memory(store, thread_id))

Every wrapped tool keeps its name, description and args schema; calls go
through `ToolBoundary.gate` / `finish`, so taint, policy, labels and the signed
audit log behave exactly as in the reference agent loop. Record the user's
turn with `boundary.record_user(text, session)` before invoking the graph.
"""

from __future__ import annotations

from typing import Callable

from langchain_core.tools import BaseTool, StructuredTool

from ..boundary import ToolBoundary
from ..memory import ProvenanceMemoryStore

SessionArg = str | Callable[[], str]


def _sid(session: SessionArg) -> str:
    return session() if callable(session) else session


def gate_tool(tool: BaseTool, boundary: ToolBoundary, session: SessionArg) -> BaseTool:
    def run(**kwargs):
        g = boundary.gate(tool.name, kwargs, _sid(session))
        out = tool.invoke(kwargs) if g.execute else None
        return boundary.finish(g, out).output

    async def arun(**kwargs):
        g = boundary.gate(tool.name, kwargs, _sid(session))
        out = await tool.ainvoke(kwargs) if g.execute else None
        return boundary.finish(g, out).output

    return StructuredTool.from_function(func=run, coroutine=arun, name=tool.name,
                                        description=tool.description, args_schema=tool.args_schema)


def gate_tools(tools: list[BaseTool], boundary: ToolBoundary, session: SessionArg) -> list[BaseTool]:
    return [gate_tool(t, boundary, session) for t in tools]


def memory_tools(store: ProvenanceMemoryStore, boundary: ToolBoundary, session: SessionArg) -> list[BaseTool]:
    """`memory_write` / `memory_read` tools whose labels are assigned by the boundary."""

    def memory_write(note: str) -> str:
        """Store a durable note (fact or instruction about the user's preferences) for future sessions."""
        g = boundary.gate("memory_write", {"note": note}, _sid(session), labelled=True)
        out = None
        if g.execute:
            out = f"Saved to memory ({store.write(note, g.kwargs['_label'], g.kwargs['_derived_from']).id})."
        return boundary.finish(g, out).output

    def memory_read() -> str:
        """Return everything currently stored in memory."""
        g = boundary.gate("memory_read", {}, _sid(session))
        return boundary.finish(g, boundary.inject_memory(store, _sid(session)) if g.execute else None).output

    return [StructuredTool.from_function(memory_write), StructuredTool.from_function(memory_read)]
