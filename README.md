# OpenClaw Onchain Overseer

A guardrail gateway for LLM agents. It sits in front of an agent runtime as a reverse proxy,
inspects traffic in both directions, and enforces a **capability profile** that can be demoted
mid-session when risk signals fire. Violations are recorded in Postgres and anchored on-chain.

> **Status:** early. The async audit/enforcement components exist; the gateway does not yet.
> Each section below is marked **[built]**, **[partial]**, or **[planned]**.

---

## Architecture

```
                    +-------------------+
                    |   Client / User   |
                    +---------+---------+
                              |
                              v
                 +----------------------------+
                 |   Go Guardrail Gateway     |
                 | (Context Loader & Session) |
                 +-------------+--------------+
                               |
                      [Inbound Inspection]
                               |
            +------------------+------------------+
            |                                     |
            v                                     v
  +-------------------+              +------------------------+
  |  Fast Heuristics  |              |     Llama Guard 3      |
  | (Regex, Entropy,  |              |  (Inference Svc via    |
  |   Token Spikes)   |              |     vLLM / Ollama)     |
  +---------+---------+              +-----------+------------+
            |                                     |
            +------------------+------------------+
                               |
                               v
              +--------------------------------+
              |    Capability & Risk Engine    | <--- Postgres
              |  - Updates session risk score  |      (history & state)
              |  - Computes capability profile |
              +---------------+----------------+
                              |
              +---------------+----------------+
              | Hard Block  -> terminate early |
              | Downgrade   -> mutate tool set |
              +---------------+----------------+
                              |
                              v
               +------------------------------+
               |    Upstream Agent Execution  |
               |   (LLM + Restricted Tools)   |
               +---------------+--------------+
                               |
                     [Outbound Inspection]
                               |
                               v
               +------------------------------+
               |  tool_call allowlist check   |
               |  Llama Guard 3 output scan   |
               +---------------+--------------+
                               |
                               v
               +------------------------------+
               | Audit Logger (Async Worker)  | ---> Postgres + chain
               +---------------+--------------+
                               |
                               v
                        Response to User
```

Two services, deliberately separate:

| | Gateway | Overseer (async) |
|---|---|---|
| Mode | Synchronous, in the request path | Batch worker |
| Budget | Milliseconds | Seconds to minutes |
| Job | Inspect, demote, splice tools, block | Deep evaluation, on-chain anchoring |
| Status | **[planned]** | **[partial]** |

---

## Capability profiles **[planned]**

Execution capability is a **tier**, not a boolean. A session starts at a configured level and is
demoted when risk signals fire. Every request is served under the session's current profile.

| Level | Name | Allowed Capabilities | Tool Access | Model Routing |
|---|---|---|---|---|
| 0 | Full / Unrestricted | Read/Write/Exec | Shell, SQL Execute, Web Search, File I/O | Primary model (full context) |
| 1 | Constrained | Read-only | Read-only SQL, Search, Static APIs | Primary model (strict system prompt) |
| 2 | Quarantined | Conversational only | **None** — tool payload stripped | Lightweight model / strict guard prompt |
| 3 | Hard Block | Terminated | None | Pre-compiled static refusal |

**Demotion is a ratchet.** Within a session, level only ever increases (capability only
decreases). Re-promotion, if allowed at all, must be an explicit policy decision with a decay
window — never an automatic consequence of one clean request. At level 3 the upstream model is
never contacted; the gateway returns a static refusal.

---

## Inspection pipeline **[planned]**

### Inbound

Both layers run **concurrently** and join before the risk engine — the semantic gate is
asynchronous in the sense that it does not block the heuristics leg, but the joined result does
gate the request.

1. **Fast heuristics** (in-process, sub-millisecond): regex pattern matches, Shannon entropy
   detection over the prompt, token-count spikes against the session baseline.
2. **Semantic gate**: RPC/HTTP to a dedicated Llama Guard 3 inference server (vLLM or Ollama),
   mapping the prompt against standard safety taxonomies — hate, violence, self-harm,
   cyberattacks, software vulnerabilities.

The **Capability & Risk Engine** consumes both verdicts plus historical state from Postgres,
updates the session risk score, and computes the resulting profile.

**On semantic-gate timeout or outage the session demotes** (fail closed). Failing open here would
make the guard trivially bypassable by inducing load on the inference service.

### Tool splicing

The gateway acts as a reverse proxy: it receives the agent prompt *and* the tool registry. In
modern tool calling the client re-sends the full JSON-schema `tools[]` array on every run, which
is exactly what makes interception possible — before forwarding upstream, the gateway rewrites
`tools[]` to contain only the tools permitted at the current level. **Below level 2, no tools are
forwarded at all.**

This requires a mapping from concrete tool name to capability category (Shell / SQL Execute /
Web Search / File I/O / read-only SQL / static API). That classification is a registry concern and
is not yet specified.

### Outbound

Splicing the request is necessary but not sufficient — prior turns in the message history still
reference tools that have since been stripped, so a model can still emit a call for one. The
outbound layer is the backstop, not a duplicate:

1. **`tool_call` interception** — evaluate every requested call against the current allowlist
   *before execution*. A hallucinated or coerced call to a disabled or out-of-bounds tool is
   intercepted here.
2. **Output scan** — Llama Guard 3 over the generated assistant text before it returns to the
   client.
3. **Audit logging** — asynchronous; writes violations, prompts, and risk diffs to Postgres and
   anchors them on-chain.

---

## Data model

**[built]** `boundaries`, `violations` — see `schema.sql`.

**[planned]** Session and risk state. The gateway needs at minimum: per-session capability level
and risk score, an append-only log of risk events (which layer fired, score delta, taxonomy
category), and a record of intercepted tool calls. A canonical schema for these is still to be
agreed — the tables in `schema.sql` today cover only the async auditor.

`actions` is **owned by another team** and appears in `schema.sql` for reference only.

---

## Components

| Path | Status | Notes |
|---|---|---|
| `overseer/cmd/overseer` | **[stub]** | Prints a banner; the poll loop is not wired |
| `overseer/cmd/seed` | **[built]** | Seeds `boundaries` for `$AGENT_ID`; idempotent |
| `overseer/internal/db` | **[built]** | pgxpool wrapper; four queries |
| `overseer/internal/evaluator` | **[built]** | gpt-4o-mini via langchaingo — async tail only |
| `overseer/internal/chain` | **[built]** | Audit-log and punishment contract writes |
| Gateway, heuristics, risk engine, tool splicer | **[planned]** | Not started |

---

## Build and run

```sh
go build ./...
go vet ./...
go run ./overseer/cmd/seed       # seed boundaries
go run ./overseer/cmd/overseer   # currently a stub
psql "$POSTGRES_DSN" -f schema.sql
```

### Environment

Loaded from `.env` (gitignored).

| Variable | Used by |
|---|---|
| `POSTGRES_DSN`, `AGENT_ID` | seeder, overseer |
| `OPENAI_API_KEY` | evaluator (langchaingo) |
| `ALCHEMY_RPC_URL`, `PRIVATE_KEY` | chain client |
| `AUDIT_LOG_ADDRESS`, `PUNISHMENT_ADDRESS` | chain client |
| `LLAMA_GUARD_URL` *(planned)* | semantic gate |

---

## Roadmap

1. **Async tail** — wire the overseer loop; fix the severity mismatch; transactional
   insert-and-mark; write `tx_hash` back; wait for receipts.
2. **Gateway skeleton** — reverse proxy that forwards upstream unmodified, with session loading
   and pass-through logging. Correct plumbing before any enforcement.
3. **Capability engine** — the level table, session state, the demotion ratchet, risk scoring.
   Pure and unit-testable, with no I/O.
4. **Inbound inspection** — fast heuristics, then the Llama Guard 3 client with concurrent
   fan-out, a timeout, and fail-closed demotion.
5. **Tool splicing** — tool-to-category registry, request rewriting, model routing per level,
   level-3 static refusal.
6. **Outbound inspection** — `tool_call` allowlist enforcement, output scan, async audit worker.
7. **Hardening** — load testing against the latency budget, chaos testing the inference
   dependency, end-to-end bypass attempts.

## Open questions

- Streaming responses: scanning complete assistant text conflicts with token-by-token streaming.
  Buffer, rolling-window scan, or no streaming in v1?
- Session store: in-memory with write-behind, or Postgres in the hot path?
- Is `agent_id` an Ethereum address? The chain client assumes so; the schema says `TEXT`.
- What is `rule_hash` for? It is computed at seed time and never read.
