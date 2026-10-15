# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A guardrail gateway for LLM agents. A Go reverse proxy sits inline in front of an agent runtime,
inspects inbound prompts, computes a **capability tier** for the session, rewrites the upstream
request to strip tools the session may no longer use, and inspects outbound tool calls and
assistant text. Read `README.md` for the architecture before making design decisions.

The security model (`internal/capability`), identity (`internal/auth`) and session persistence
(`internal/session`) are built and tested. **The HTTP gateway itself does not exist yet**, so none
of it is on a request path.

A second, asynchronous service — an LLM evaluator and an on-chain anchoring worker — was inherited
from the multi-team project this was forked from and has been removed; see
`migrations/0002_drop_async_tail.sql`. Do not reintroduce it.

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

The module is `openclaw/guard`, but all code lives one level down under `overseer/`, so internal
packages import as `openclaw/guard/overseer/internal/<pkg>` — not `openclaw/guard/internal/<pkg>`.
Getting this wrong is the most common build break.

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
- `overseer/internal/migrate` — migration runner. Records each file in `schema_migrations` and
  refuses to re-run one whose contents changed. **Never edit an applied migration; write the next
  one.** The schema tests live here too, since what they assert is what the migrations produce.
- `overseer/internal/dbtest` — throwaway-schema harness. `dbtest.Pool(t)` creates an isolated
  schema, applies the migration and drops it on cleanup. Finds `.env` by walking up from the
  package directory.
- `POSTGRES_DSN` — the application database
- `LLAMA_GUARD_URL` — semantic gate endpoint (phase 4)
- `TEST_POSTGRES_DSN` — database tests; they **skip silently** without it
- `REQUIRE_DB_TESTS` — set to any value to turn those skips into failures

## Unresolved design questions

Carried in `README.md` under "Open questions" — streaming vs. output scanning, session-store
placement, and where the tool registry comes from — nothing constructs one outside tests today.
Raise these rather than silently picking one.

Resolved since: the session/risk schema arrived and is built as `session_states` and
`guardrail_violations` in `migrations/0001_init.sql`. Session identity is server-issued JWT
(`internal/auth`), with risk carried forward by `user_id` over a 24-hour window.
