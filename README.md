# OpenClaw Guard

A guardrail gateway for LLM agents. It sits in front of an agent runtime as a reverse proxy,
inspects traffic in both directions, and enforces a **capability profile** that can be demoted
mid-session when risk signals fire. Every decision and its evidence are recorded in Postgres.

> **Status:** the security model, session storage and identity verification are built and
> tested. The HTTP gateway that would call them does not exist yet, so none of it is on a
> request path. Each section below is marked **[built]**, **[partial]**, or **[planned]**.

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
               | Audit Logger (Async Worker)  | ---> Postgres
               +---------------+--------------+
                               |
                               v
                        Response to User
```

One service. An earlier design had a second, asynchronous worker that evaluated actions with an
LLM and anchored violations to a blockchain; it was inherited from the multi-team project this was
forked from, and `0002_drop_async_tail.sql` removed it. See that migration for the reasoning.

## Capability profiles **[built]**

Execution capability is a **tier**, not a boolean. A session starts at a configured level and is
demoted when risk signals fire. Every request is served under the session's current profile.

| Level | Name | Allowed Capabilities | Tool Access | Model Routing |
|---|---|---|---|---|
| 0 | Full / Unrestricted | Read/Write/Exec | Shell, SQL Execute, Web Search, File I/O | Primary model (full context) |
| 1 | Constrained | Read-only | Read-only SQL, Search, Static APIs | Primary model (strict system prompt) |
| 2 | Quarantined | Conversational only | **None** — tool payload stripped | Lightweight model / strict guard prompt |
| 3 | Hard Block | Terminated | None | Pre-compiled static refusal |

**Demotion is a ratchet within a session.** Nothing on the request path lowers a tier, and at
level 3 the upstream model is never contacted.

**Across sessions, risk carries forward rather than the tier.** Risk decays, so the tier derived
from it recovers on its own. Carrying the tier instead made every demotion permanent: each new
session refreshed the carry-forward window, so a user who returned daily could never recover.

**Availability failures apply a request-scoped floor that is never stored.** If the semantic gate
is unreachable the request in front of it is restricted and nothing is written — otherwise a
minute of downtime would follow every user who happened to be online.

**One operator command lowers a tier.** `cmd/reset-user` clears a user's accumulated risk. It is
the remedy for a false positive, and it is deliberately not reachable from the request path.

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
3. **Audit logging** — asynchronous; writes violations, previews and risk diffs to Postgres
   without blocking the response.

---

## Data model

**[built]** `migrations/0001_init.sql` is the source of truth and is idempotent. It holds
`session_states` (per-session tier and cumulative risk) and `guardrail_violations` (the
append-only compliance log), plus the inherited `actions`, `boundaries` and `violations`.
`schema.sql` is superseded and kept only until the `actions` shape is settled.

Enumerated columns carry CHECK constraints deliberately, including a `downgrade_is_ratchet`
constraint that enforces the capability ratchet in the database as well as in Go, and a format
check on `content_sha256`. `updated_at` is maintained by a `BEFORE UPDATE` trigger, because
`DEFAULT NOW()` fires only on insert.

`guardrail_violations` stores a hash plus a redacted preview as the durable record;
`raw_content` is nullable and subject to a retention window.

There is **no migration runner yet**. The single migration is idempotent by construction, which
stops being achievable as soon as an `ALTER` is needed — see the hand-written guard around the
`content_sha256` constraint for what that already costs.

---

## Components

| Path | Status | Notes |
|---|---|---|
| `overseer/internal/capability` | **[built]** | Tiers, profiles, tool registry, risk scoring and decay, the ratchet. Pure, no I/O |
| `overseer/internal/auth` | **[built]** | JWT verification. Pinned algorithms, required expiry, issuer and audience checked |
| `overseer/internal/session` | **[built]** | Session load/create with cross-session carry-forward; transactional decision writes under a row lock |
| `overseer/internal/migrate` | **[built]** | Migration runner; refuses to re-run an edited migration |
| `overseer/internal/config` | **[built]** | Env loading with aggregated fail-fast validation |
| `overseer/internal/dbtest` | **[built]** | Throwaway-schema harness for database tests |
| `overseer/cmd/migrate` | **[built]** | Applies pending migrations; `-dry-run` gates a deploy |
| `overseer/cmd/reset-user` | **[built]** | Clears a user's risk. The only path that lowers a tier |
| Gateway, heuristics, tool splicer | **[planned]** | Not started. Nothing above is on a request path yet |

---

## Build and run

```sh
go build ./...
go vet ./...
go run ./overseer/cmd/migrate            # apply pending migrations
go run ./overseer/cmd/migrate -dry-run   # list pending; non-zero exit if any
go run ./overseer/cmd/reset-user -user X # clear a user's accumulated risk
psql "$POSTGRES_DSN" -f migrations/0001_init.sql
```

### Environment

Loaded from `.env` (gitignored).

| Variable | Used by |
|---|---|
| `POSTGRES_DSN` | the application database |
| `LLAMA_GUARD_URL` *(phase 4)* | semantic gate endpoint |
| `TEST_POSTGRES_DSN` | database tests; they **skip silently** without it |
| `REQUIRE_DB_TESTS` | set to any value to turn those skips into failures |

## Roadmap

1. ~~**Capability engine** — the level table, the demotion ratchet, risk scoring and decay.
   Pure and unit-testable, with no I/O.~~ **Done.**
2. ~~**Identity and session storage** — JWT verification, session load/create with
   cross-session carry-forward, transactional decision writes under a row lock.~~ **Done.**
3. **Gateway skeleton** — reverse proxy forwarding upstream unmodified, with session loading and
   pass-through logging. Correct plumbing before any enforcement. Define the `Inspector` interface
   here even though nothing implements it yet, so phase 4 plugs in rather than carves out.
   **Next.**
4. **Inbound inspection** — fast heuristics in-process, plus a Llama Guard 3 client, both legs in
   flight concurrently under a shared deadline. Timeout or outage applies a request-scoped floor
   (see `capability.EffectiveTier`), never a persisted demotion. Log-only until the latency budget
   is measured.
5. **Tool splicing** — tool-to-category registry, request rewriting, model routing per tier,
   tier-3 static refusal.
6. **Outbound inspection** — `tool_call` allowlist enforced before execution, output scan, async
   audit writer.
7. **Evaluation** — a labelled corpus (benign / injection / harmful) and an offline scoring
   script. The thresholds are arbitrary until something measures the false-positive rate, and
   since a demotion restricts a real user, that is the number that decides whether this is usable.
8. **Hardening** — load testing against the latency budget, chaos-testing the inference
   dependency, deliberate bypass attempts.

## Decisions

**No streaming in v1.** `stream: true` is rejected with a clear error rather than silently
buffered.

Scanning complete assistant text is fundamentally at odds with token-by-token delivery: once a
token has been forwarded it cannot be recalled, so a scanner that fires at token 500 is reporting
something it can no longer act on. Streaming also removes the ability to change the status code
once the response has begun, so a violation found mid-stream has to be expressed inside the
stream rather than as a 403.

Buffering upstream and re-emitting as chunks was considered and rejected. It looks like the
compatible option but is the worst of the three: time-to-first-token becomes full generation
time, so the entire user-visible benefit of streaming is lost while all of its complexity is
kept — and the client is told something untrue about what happened.

Worth revisiting later, because the two outbound jobs behave oppositely under streaming. A tool
call's name arrives in its first delta, so interception is actually *easier* mid-stream; only
text scanning is blocked. The eventual shape is likely "stream tokens, buffer at tool-call
boundaries", which is more than v1 needs.

**The gateway is invisible in shape, loud in telemetry.** Same request and response format, so
pointing a base URL at it is the only client change required. But enforcement is never silent:
every strip, interception and tier change is logged against a `request_id`. A tool stripped with
no log line is indistinguishable from a model regression, and would be debugged as one.

Clients receive that `request_id` in a response header — enough to quote in a support ticket,
not enough to learn anything. The tier is deliberately **not** exposed to clients: a number that
changes as you probe is an oracle for the thresholds.

**Llama Guard 3 8B, not 1B.** The 1B exists for on-device use where 5GB of weights is not
available; it trades accuracy for that. Accuracy matters here specifically because false positives
restrict real users, and the hardware has the headroom. The model is a config value rather than a
constant, so once the phase 7 corpus exists this becomes a measurement rather than a judgement.

**A stub inspector alongside the real one.** Tests and CI run against a deterministic stub behind
the same interface; the demo runs against Ollama. A guardrail whose test suite needs a GPU does
not get run.

## Open questions

- Session store: in-memory with write-behind, or Postgres in the hot path?
- Where does the tool registry come from — a static map, an operator-editable config file, or a
  per-agent table? Nothing constructs one outside tests today.
- Does an unclassified inbound tool name get recorded as a `TOOL_VALIDATOR` event, or silently
  stripped? Silent stripping is indistinguishable from a model regression.
