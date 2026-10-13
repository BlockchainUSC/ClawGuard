-- 0001_init.sql — consolidated schema for OpenClaw Guard.
--
-- Supersedes schema.sql, which is retained for reference until the inherited
-- `actions` table's shape is settled (Phase 8). Idempotent: safe to re-run.
--
-- Enumerated columns carry CHECK constraints deliberately. The one defect
-- already shipped in this repo is a vocabulary mismatch between Go code and a
-- CHECK constraint; enumerations belong in the database where they can be
-- enforced rather than assumed.

BEGIN;

-- ---------------------------------------------------------------------------
-- Gateway state (Phases 1-6)
-- ---------------------------------------------------------------------------

-- Per-session capability tier and cumulative risk. user_id is indexed because
-- new sessions carry risk forward from that user's recent history; without it
-- the capability ratchet is bypassable by reconnecting.
CREATE TABLE IF NOT EXISTS session_states (
    session_id   UUID PRIMARY KEY,
    user_id      VARCHAR(128) NOT NULL,
    current_tier INT NOT NULL DEFAULT 0 CHECK (current_tier BETWEEN 0 AND 3),
    risk_score   INT NOT NULL DEFAULT 0 CHECK (risk_score >= 0),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_risk ON session_states(risk_score);
CREATE INDEX IF NOT EXISTS idx_session_user ON session_states(user_id, updated_at DESC);

-- Append-only compliance and debugging log.
--
-- raw_content is nullable and subject to a retention window. content_sha256 and
-- content_preview are the durable record: storing offending text verbatim and
-- forever would make this table the system of record for the PII that the
-- "must not output personal identifying information" boundary exists to prevent.
CREATE TABLE IF NOT EXISTS guardrail_violations (
    id                     BIGSERIAL PRIMARY KEY,
    session_id             UUID NOT NULL REFERENCES session_states(session_id),
    direction              VARCHAR(16) NOT NULL
                               CHECK (direction IN ('INBOUND', 'OUTBOUND')),
    violation_source       VARCHAR(32) NOT NULL
                               CHECK (violation_source IN ('FAST_REGEX', 'ENTROPY',
                                      'TOKEN_SPIKE', 'LLAMA_GUARD_3', 'TOOL_VALIDATOR')),
    llama_guard_code       VARCHAR(32),
    content_sha256         CHAR(64) NOT NULL,
    content_preview        TEXT NOT NULL,
    raw_content            TEXT,
    applied_downgrade_from INT CHECK (applied_downgrade_from BETWEEN 0 AND 3),
    applied_downgrade_to   INT CHECK (applied_downgrade_to BETWEEN 0 AND 3),
    metadata               JSONB,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The capability ratchet, enforced in the database as well as in Go.
    CONSTRAINT downgrade_is_ratchet CHECK (
        applied_downgrade_from IS NULL
        OR applied_downgrade_to IS NULL
        OR applied_downgrade_to >= applied_downgrade_from
    )
);

CREATE INDEX IF NOT EXISTS idx_violations_session
    ON guardrail_violations(session_id, created_at DESC);

-- DEFAULT NOW() only fires on INSERT, so updated_at needs a trigger or it stays
-- permanently equal to created_at. clock_timestamp() rather than now() so the
-- value advances even within a single transaction.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_session_states_updated_at ON session_states;
CREATE TRIGGER trg_session_states_updated_at
    BEFORE UPDATE ON session_states
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Inherited tables (async overseer, Phase 8)
-- ---------------------------------------------------------------------------

-- `actions` came from the club's multi-team design, where another team's agent
-- was the producer. Under the current plan the gateway becomes that producer.
-- Shape is unchanged pending that decision.
CREATE TABLE IF NOT EXISTS actions (
    id          SERIAL PRIMARY KEY,
    agent_id    TEXT        NOT NULL,
    action_type TEXT        NOT NULL,
    payload     JSONB       NOT NULL DEFAULT '{}',
    evaluated   BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_actions_evaluated ON actions(evaluated, created_at);

CREATE TABLE IF NOT EXISTS boundaries (
    id         SERIAL PRIMARY KEY,
    agent_id   TEXT        NOT NULL,
    rule       TEXT        NOT NULL,
    rule_hash  CHAR(64)    NOT NULL,
    active     BOOLEAN     NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agent_id, rule_hash)
);

CREATE TABLE IF NOT EXISTS violations (
    id          SERIAL PRIMARY KEY,
    agent_id    TEXT        NOT NULL,
    action_id   INTEGER     NOT NULL,
    boundary_id INTEGER     NOT NULL REFERENCES boundaries(id),
    severity    TEXT        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    reasoning   TEXT        NOT NULL,
    tx_hash     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_violations_agent ON violations(agent_id);
CREATE INDEX IF NOT EXISTS idx_violations_action ON violations(action_id);

COMMIT;
