# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A guardrail system for LLM agents, being built as **two services with different execution models**.
Read `README.md` for the full architecture before making design decisions.

1. **Guardrail Gateway** *(planned — no code yet)*. A synchronous Go reverse proxy in the request
   path. It inspects inbound prompts via two concurrent layers (in-process fast heuristics; a
   Llama Guard 3 inference service over RPC/HTTP), computes a **capability profile** for the
   session, rewrites the upstream request accordingly, then inspects outbound `tool_call`s and
   assistant text. Latency-critical.
2. **Overseer** *(what currently exists)*. An async batch worker that polls the shared `actions`
   table, evaluates against boundaries with an LLM, and anchors violations on-chain. This is the
   "Audit Logger (Async Worker)" tail in the architecture diagram. Not latency-sensitive.

**Do not conflate these.** Everything in `overseer/` today belongs to service 2. The gateway is a
new tree. `internal/db` and `internal/chain` are shared; `internal/evaluator` (gpt-4o-mini via
langchaingo) is for the async tail only — inline semantic inspection uses Llama Guard 3 instead.

## Capability profiles (the central concept)

Execution capability is a tier (0 Full / 1 Constrained / 2 Quarantined / 3 Hard Block), not a
boolean. Sessions are **demoted** when risk fires. Invariants that must hold in any implementation:

- **Demotion is a ratchet *within a session*** — nothing on the request path ever lowers a tier.
  Do not add auto-recovery on a clean request.
- **Across sessions, risk carries forward, not tier.** `carryForward` decays each of the user's
  recent sessions' risk and re-derives a tier from the worst. Carrying the tier made demotion
  permanent: each new session stamps a fresh `updated_at`, the window slides, and one minute of
  inference downtime would quarantine a daily user for life.
- **Availability failures use a floor, not a signal.** `capability.EffectiveTier(stored, floor)`
  restricts the request in front of it and persists nothing. "The guard is down" and "this user is
  dangerous" are different claims; only the second is evidence worth remembering.
- **`session.Store.ResetUser` is the only path that lowers a tier**, and it is an operator command
  (`cmd/reset-user`), unreachable from the request path. Without it a false positive has no remedy.
- **Below level 2, the `tools[]` array is stripped entirely** before forwarding upstream.
- **Level 3 never contacts the upstream model** — it returns a pre-compiled static refusal.
- **The semantic gate fails closed.** If Llama Guard 3 times out or is unreachable, demote. Failing
  open makes the guard bypassable by loading the inference service.
- **Outbound `tool_call` checking is not redundant with inbound splicing.** Message history still
  references stripped tools, so the model can emit calls for them. It is the backstop.

## Commands

All Go commands run from the repo root (the module root).

```sh
go build ./...                  # build everything
go run ./overseer/cmd/migrate            # apply pending migrations
go run ./overseer/cmd/migrate -dry-run   # list pending; exits non-zero if any
go run ./overseer/cmd/reset-user -user X # clear a user's risk (operator escape hatch)
go vet ./...                    # static checks
go test ./...                   # pure tests; db tests SKIP without a DSN
go run ./overseer/cmd/seed      # seed boundaries for $AGENT_ID
go run ./overseer/cmd/overseer  # still a stub main
psql "$POSTGRES_DSN" -f migrations/0001_init.sql   # apply schema (idempotent)
```

Database tests need `TEST_POSTGRES_DSN` and **skip silently without it** — a green
`go test ./...` does not mean the schema was exercised. Always set the DSN before claiming
the suite passes:

```sh
TEST_POSTGRES_DSN='postgres://postgres@127.0.0.1:55432/openclaw_test?sslmode=disable' go test ./...
go test -run TestMigration_UpdatedAtAdvancesOnUpdate ./overseer/internal/db/   # single test
```

No Postgres running? Homebrew's binaries are installed but no cluster is. Spin up a throwaway
one on a non-default port (TCP only — the scratchpad path exceeds the 103-byte Unix socket
limit, and the default port may collide):

```sh
initdb -D "$PGDIR" -U postgres --auth=trust
pg_ctl -D "$PGDIR" -o "-p 55432 -c listen_addresses=127.0.0.1 -c unix_socket_directories=" \
       -l "$PGDIR/server.log" start
createdb -h 127.0.0.1 -p 55432 -U postgres openclaw_test
# ... run tests ...
pg_ctl -D "$PGDIR" stop -m fast
```

Each db test builds an isolated schema and drops it on cleanup, so it never touches
application tables.

`go.mod` declares `go 1.25.0`; a newer local toolchain is fine.

## Layout and import paths

The module is `openclaw/oversight`, but all code lives one level down under `overseer/`, so
internal packages import as `openclaw/oversight/overseer/internal/<pkg>` — not
`openclaw/oversight/internal/<pkg>`. Getting this wrong is the most common build break.

- `overseer/cmd/overseer` — service entrypoint. Still a stub (`main` only prints a banner and
  blank-imports the deps); the poll → evaluate → act loop is not wired up yet.
- `overseer/cmd/seed` — one-shot seeder. Its `rules` slice is the source of truth for boundary
  text; `rule_hash` is `sha256(rule)` hex, and the `(agent_id, rule_hash)` unique constraint plus
  `ON CONFLICT DO NOTHING` makes re-running safe. Editing a rule's text creates a new row rather
  than updating the old one, so stale boundaries must be deactivated by hand.
- `overseer/internal/capability` — **the security model.** Tiers, profiles, the tool registry,
  risk scoring and decay, and `Policy.Decide` (the ratchet). Pure: no I/O, no clock reads, no
  mutable state a caller can reach. `now` is a parameter so decay is deterministic under test.
  Keep it that way — this is the one place where a bug is a security bug rather than an outage.
  Every fallback fails closed: an invalid tier resolves to `TierBlocked`, an unknown tool name
  resolves to denied, and the zero `Profile` grants nothing.
- `overseer/internal/config` — env loading with aggregated fail-fast validation. `Require` reports
  every missing variable at once, by name. Per-component requirement sets (`RequiredForGateway`,
  `RequiredForChain`, …) so a process only demands what it uses.
- `overseer/internal/auth` — JWT verification. The parser pins algorithms, requires `exp`, and
  checks issuer and audience. `User.Verified` records whether the gateway checked a signature
  itself; it travels into the audit trail and is **not** stored on the session, because it
  describes the request's credential rather than the session.
- `overseer/internal/session` — `session_states` and `guardrail_violations`. Two invariants to
  preserve: a session id is **not** authorisation (`loadByID` compares `user_id`, returning
  `ErrSessionNotOwned`, which callers must render identically to "not found" so the endpoint is
  not a session-id oracle); and risk is stored as **decay recomputed under the row lock plus
  `Decision.SignalDelta`**, never as one combined delta — decay applies once per elapsed period,
  signal weight once per evaluation, and conflating them let concurrent requests drain risk to
  zero.
- `overseer/internal/dbtest` — throwaway-schema harness. `dbtest.Pool(t)` creates an isolated
  schema, applies the migration and drops it on cleanup. Finds `.env` by walking up from the
  package directory.
- `overseer/internal/db` — pgxpool wrapper. The intended cycle is
  `GetUnevaluatedActions` → `GetActiveBoundaries` → `InsertViolation` → `MarkEvaluated`.
  Actions are polled 50 at a time, oldest first. `Payload` is kept as raw JSONB bytes and passed
  to the LLM verbatim.
- `overseer/internal/evaluator` — single stateless `Evaluate` call via langchaingo + OpenAI
  (`gpt-4o-mini`, temperature 0). The prompt asks for bare JSON; a parse failure returns
  `IsSuspicious: false` alongside the error, so callers must check the error rather than trust the
  zero value. Note it constructs a fresh `openai.New` client on every call.
- `overseer/internal/chain` — Ethereum writer. Contract ABIs are inline JSON string literals
  (`auditLogABI`, `punishmentABI`) rather than generated bindings, and calls go out through
  `bind.RawTransact`. `LogViolation`, `Suspend`, and `Shutdown` return the tx hash immediately and
  do **not** wait for a receipt, so a returned hash is not proof of success. `agentID` is parsed
  with `common.HexToAddress`, which silently yields the zero address for non-hex input.

## Database

`migrations/` is applied by `internal/migrate`, which records each file in `schema_migrations`
and refuses to re-run one whose contents changed. **Do not edit an applied migration — write
`0002`.** Idempotency is now the ledger's job, not the SQL's, which is what lets a migration
contain `ALTER`.

`migrations/0001_init.sql` is the source of truth. It holds the gateway tables
(`session_states`, `guardrail_violations`) plus the inherited `actions` / `boundaries` /
`violations`. `schema.sql` is superseded but retained until the `actions` shape is settled.

Enumerated columns carry CHECK constraints deliberately — `current_tier`, `risk_score`,
`direction`, `violation_source`, and a `downgrade_is_ratchet` constraint that enforces the
capability ratchet in the database as well as in Go. `updated_at` is maintained by a
`BEFORE UPDATE` trigger using `clock_timestamp()`, because `DEFAULT NOW()` fires only on insert.

`guardrail_violations` stores `content_sha256` + a redacted `content_preview` as the durable
record; `raw_content` is nullable and subject to a retention window. Storing violating text
verbatim forever would make the audit log the system of record for the PII that the
"must not output personal identifying information" boundary exists to prevent.

## Environment

Loaded from `.env` via godotenv (gitignored; there is no committed example file).

- `POSTGRES_DSN`, `AGENT_ID` — required by the seeder
- `ALCHEMY_RPC_URL`, `PRIVATE_KEY`, `AUDIT_LOG_ADDRESS`, `PUNISHMENT_ADDRESS` — required by
  `chain.New`; all are checked up front and missing values are hard errors
- `OPENAI_API_KEY` — read by langchaingo for the evaluator

Note that `cmd/overseer` does not currently call `godotenv.Load()`; only `cmd/seed` does.

## Unresolved design questions

Carried in `README.md` under "Open questions" — streaming vs. output scanning, session-store
placement, whether `agent_id` is an Ethereum address, and the unused `rule_hash`. The tool-name to
capability-category mapping is also unspecified. Raise these rather than silently picking one.

Resolved since: the session/risk schema arrived and is built as `session_states` and
`guardrail_violations` in `migrations/0001_init.sql`. Session identity is server-issued JWT
(`internal/auth`), with risk carried forward by `user_id` over a 24-hour window.

## Known inconsistency to resolve

The severity vocabularies disagree. `evaluator`'s prompt asks for `"warn" | "suspend" | "shutdown"`
(action-shaped, matching the `chain` methods), while the `violations.severity` CHECK constraint in
`schema.sql` only accepts `low | medium | high | critical`. Passing the LLM's severity straight
into `InsertViolation` will violate the constraint. Pick one vocabulary (or add an explicit
mapping) before wiring the main loop. Related: `chain.LogViolation` takes an `actionHash [32]byte`
that nothing in the codebase computes yet.
