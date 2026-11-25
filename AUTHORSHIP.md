# Authorship

This project was built with AI assistance. This file records who wrote what, because
an unqualified "I built this" would be untrue and because the parts that *are* mine
read better when they are not lumped in with the rest.

## How to verify any of this

Every commit made with AI assistance carries a `Co-Authored-By: Claude` trailer.
Commits without it are unassisted.

```sh
# Assisted
git log --grep='Co-Authored-By: Claude' --oneline

# Unassisted — mine alone, or inherited from the fork
git log --format='%H %h %s' | while read -r full short subj; do
  git log -1 --format='%B' "$full" | grep -q 'Co-Authored-By: Claude' || echo "$short  $subj"
done
```

Note that `git blame` is **not** a useful signal here: every commit after the fork is
authored `JonahE210`, because they were all made from my machine with my git config.
The trailer is the real record.

## Inherited

Commits `24a28e2`, `4292c55`, `f359afa` are from the university club repo this was
forked from, authored by Anthony Colin. That code — an LLM evaluator, an on-chain
anchoring client, a stub entrypoint — was removed in `d8bf51a` and
`migrations/0002_drop_async_tail.sql`. None of it remains.

## Phases 1-3 — assisted

The capability engine, session storage, JWT verification, migration runner and gateway
were written with AI assistance. I directed the work rather than typing most of it.

What that actually involved, stated plainly so it is neither inflated nor erased:

- **Architectural decisions were mine.** JWT over API keys for identity. Cutting the
  on-chain phase. No streaming in v1. Llama Guard 8B over 1B. Deferring a dedicated
  injection classifier until there is a corpus to justify it. Each of these changed
  what got built.
- **I asked for the reviews that found the bugs.** A redundancy pass and an
  architecture review turned up four fail-open defects and one design flaw that would
  have permanently quarantined users during an inference outage. Commissioning and
  acting on those was my call.
- **Two functions in phase 2 I wrote myself**, against tests written for me, with
  review and correction: `auth.JWTAuthenticator.WhoIs` and
  `session.PostgresStore.LoadOrCreate`. Both took several iterations.

## Phase 4 — deliberately split

Inbound inspection is divided so the work is attributable.

| Component | Who |
|---|---|
| `inspect` seam move, per-inspector `Mode` | Assisted |
| All test files in `internal/inspect` | Assisted |
| `inspect.Hash`, `inspect.Redact` | Mine |
| `inspect.Preview` — bounding and redaction rules | Assisted. I wrote the first version and got stuck on the redaction loop |
| `inspect.ShannonEntropy` | Mine |
| `inspect.SpikeRatio` | Mine |
| `injectionRules`, `inspect.MatchesInjection` | Mine |
| `Heuristics.Inspect` wiring | Mine |
| Llama Guard response parser | Mine |
| Ollama transport, `LlamaGuard` client | Assisted |
| Violation recording path, `Record`, capture flag | Assisted |

The split is not arbitrary. Self-contained algorithms with clear inputs and outputs are
mine. Mechanical refactors, transaction-touching code and security-critical wiring —
where a subtle mistake fails open rather than loudly — are assisted.

Each of my pieces was written against failing tests that specify the behaviour, one
function at a time.

Where review changed something, it is recorded rather than quietly folded in. The
redaction rules in `Preview` are the clearest case: my first list included a `\w{8,}`
pattern that would have masked every word of eight or more characters in every stored
preview, and a ten-digit rule ordered before a sixteen-digit one, which would have left
the last six digits of a card number exposed. Both were replaced.
