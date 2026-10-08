# Decisions

Choices made while building this that a reviewer may want to check or argue with.

## Scenario content

- **Attacker addresses use the reserved `.example` TLD** (RFC 2606/6761), e.g.
  `archive-compliance@mail-archive-svc.example`, not the spec's `mail-archive-svc.com`.
  This is a public repo and people will paste these payloads into real agents. A
  registrable domain could be bought to harvest whatever leaks. Trade-off: a careful
  model *might* treat `.example` as a test signal and resist more often than it would
  with a realistic domain. To measure that, change the YAML; nothing else depends on it.
- **v2 (softer phrasing)**: the mock stores a *paraphrase* rather than the verbatim
  page text, so this variant exercises the identifier rule rather than the substring rule.
- **v3 (inbox + forward)**: needed a `forward_email` tool not in the spec's tool list.
  It is policed like `send_email` (`to`, `note`). Session 3's user request is clean ("take
  care of it the way I like") but deliberately leaves room for memory to shape the action.
- **A fourth scenario, `memory_bcc_paraphrase_bypass`**, demonstrates the limitation the spec
  asked for: the address is described rather than spelled, so the v1 matcher assigns no
  untrusted taint and the attack succeeds with the defense on. It is marked
  `expect_bypass: true` and the eval labels it as such.

## memgate semantics

- **Identifiers are masked before substring matching.** Without this, `@example.com`
  (12 chars) shared between an untrusted inbox sender and the user's own `jordan@example.com`
  tainted the legitimate `to` field (a false positive found while building the demo).
  Identifiers are now attributed only by the first-seen rule, and prose only by spans.
- **User messages are recorded in the ledger** (source `user`, USER trust). The first-seen
  rule needs this. Otherwise an address the user typed would have no origin, or would get
  the origin of a later untrusted mention.
- **The ledger persists across sessions** (spec: "this or any prior session"). It lives in
  memory for one run. `ProvenanceMemoryStore.save/load` persists memory; ledger persistence
  across processes is not implemented.
- **`sources:` section added to the policy YAML.** The boundary needs to know which tool
  outputs to record and at what trust. Unlisted tools default to `untrusted` (fail closed).
- **`untrusted_memory` added to `memory_write.quarantine_if_tainted_by`.** Without it, the
  model could launder a quarantined note into trusted memory by re-writing it.
- **Labels for non-tainted memory writes are `source=agent, trust=USER`.** Spec only
  constrains the tainted case.
- **RequireConfirm in non-interactive runs auto-declines.** There is nobody to ask. The
  demo has `--confirm ask` for a live prompt.
- **Blocked calls return a tool result to the model** (`BLOCKED by memgate: ... Reason: ...`)
  rather than raising, so the session can continue.
- **Defense off uses the same boundary** with a permissive policy and a non-quarantining
  store. Labels and the signed log are still produced, so the undefended run can be audited.
  Only enforcement differs.
- **When rendering memory, `memory_read` is listed as a tool but memory is also
  pre-injected** into the system prompt each session, per the spec's system prompt.

## Mock provider

- It reads only its context window (system prompt incl. memory, user turn, tool results)
  and identifies the session by the user's message text. It is never told the defense
  setting. With the defense on it still obeys the quarantined note (worst-case model);
  the boundary has to stop it. `tests/test_e2e.py::test_mock_gets_no_defense_signal`
  asserts it emits identical tool calls in both arms.
- In the paraphrase-bypass scenario the mock's "decoding" of the described address is
  scripted. Whether real models decode it is what the eval measures.

## Providers and models

- **Anthropic default: `claude-sonnet-5-5`.** The spec named `claude-sonnet-4-5` and asked for
  current IDs. Sonnet 5.5 is the current Sonnet. Thinking is left at the model default
  (adaptive) and native content blocks, including thinking blocks, are replayed verbatim.
  Server-side refusal fallbacks are *deliberately not enabled*: silent rerouting to
  another model would corrupt per-model results. Refusals are recorded (`stop_reason=refusal`)
  instead.
- **OpenAI default `gpt-5.5`, Gemini default `gemini-3.6-flash`: unverified.** A web search
  turned up mostly third-party pages that disagreed with each other. `gpt-5.5` is
  the model OpenAI's own changelog recommended as of mid-2026. `gemini-2.0-flash` (spec)
  appears to be retired. Check both against the vendors' model lists and pass `--model` if
  they are wrong.
- OpenAI uses Chat Completions (not Responses) so any OpenAI-compatible endpoint
  (`OPENAI_BASE_URL`, e.g. Ollama) works.
- No real-provider runs were made while building this. No keys were available. The adapters are
  covered by offline tests (`tests/test_providers_offline.py`) that feed real SDK response
  types through a fake transport.

## Skipped

- `memgate/adapters/langgraph.py`: skipped (the spec allows this). The boundary is a plain
  `call(name, args, session)` and wraps any framework's tool dispatch in a few lines.
