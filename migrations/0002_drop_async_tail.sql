-- 0002_drop_async_tail.sql
--
-- Removes the inherited async-worker tables along with the Go packages that
-- used them (internal/chain, internal/evaluator, internal/db, cmd/seed,
-- cmd/overseer).
--
-- That half of the project came from the multi-team design this repo was
-- forked from: another team's agent wrote `actions`, this one consumed it and
-- anchored violations on-chain. Working solo there is no producer, the
-- contracts were never written, and the capability gateway is the product.
-- Carrying a half-built second subsystem made the finished one harder to read.
--
-- This is also the migration that could not be an edit to 0001. The runner has
-- 0001 recorded with a checksum and refuses to re-run a file whose contents
-- changed, which is the whole reason it exists.

BEGIN;

-- violations references boundaries, so it goes first.
DROP TABLE IF EXISTS violations;
DROP TABLE IF EXISTS boundaries;
DROP TABLE IF EXISTS actions;

COMMIT;
