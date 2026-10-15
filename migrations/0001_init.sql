-- 0001_init.sql — schema for OpenClaw Guard.
--
-- Applied by overseer/internal/migrate, which records each file in
-- schema_migrations and refuses to re-run one whose contents have changed.
-- Once this file has been applied to a database you care about, do not edit it:
-- write 0002 instead.
--
-- Enumerated values are constrained in the database deliberately. The one
-- defect this project shipped was a vocabulary mismatch between Go and a CHECK
-- constraint; enumerations belong where they can be enforced.

BEGIN;

-- ---------------------------------------------------------------------------
-- Gateway state
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS session_states (
    session_id   UUID PRIMARY KEY,

    -- TEXT, not VARCHAR(n): this is a JWT subject and its length is the
    -- identity provider's business. A bounded column turns a long-but-valid
    -- token into a 500 at insert time rather than a validation error at the
    -- edge.
    user_id      TEXT NOT NULL,

    -- Which agent this session is talking to. Needed for multi-agent proxying
    -- and by the on-chain client, which takes an agent identity. Nullable for
    -- now because nothing populates it until the gateway exists; it cannot be
    -- backfilled with invented values later, so the column goes in now.
    agent_id     TEXT,

    current_tier INT NOT NULL DEFAULT 0 CHECK (current_tier BETWEEN 0 AND 3),
    risk_score   INT NOT NULL DEFAULT 0 CHECK (risk_score >= 0),

    -- The thresholds that risk_score is denominated in. Recalibrating the
    -- policy would otherwise retroactively reinterpret every stored score.
    policy_version SMALLINT NOT NULL DEFAULT 1 CHECK (policy_version > 0),

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Last write of any kind. Maintained by a trigger, so anything that ever
    -- touches this row moves it.
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Last write *of the risk score*, and the baseline decay is measured from.
    --
    -- Deliberately separate from updated_at. Decay is elapsed-time sensitive,
    -- and updated_at advances on every write for any reason — the moment
    -- something adds a per-request counter or a last_seen_at, decay would
    -- silently measure nothing and risk scores would only ever increase.
    -- Written explicitly by the risk path, never by the trigger.
    risk_updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Carry-forward looks up a user's recent sessions; this serves it.
CREATE INDEX IF NOT EXISTS idx_session_user ON session_states(user_id, updated_at DESC);

-- The vocabulary of inspection layers, as a table rather than a CHECK.
--
-- A foreign key enforces it just as strictly, but adding a source (a prompt
-- injection classifier, another heuristic) becomes an INSERT instead of an
-- ALTER on the fastest-growing table in the schema.
CREATE TABLE IF NOT EXISTS violation_sources (
    source      TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

INSERT INTO violation_sources (source, description) VALUES
    ('FAST_REGEX',     'In-process pattern match'),
    ('ENTROPY',        'Shannon entropy over the prompt; noisy, low confidence'),
    ('TOKEN_SPIKE',    'Token count anomaly against the session baseline; low confidence'),
    ('LLAMA_GUARD_3',  'Content-safety classifier verdict (MLCommons hazard taxonomy)'),
    ('TOOL_VALIDATOR', 'Outbound tool_call checked against the capability allowlist')
ON CONFLICT (source) DO NOTHING;

-- Append-only compliance and debugging log.
CREATE TABLE IF NOT EXISTS guardrail_violations (
    id                     BIGSERIAL PRIMARY KEY,
    session_id             UUID NOT NULL REFERENCES session_states(session_id),

    -- Correlates every row produced by one turn: inbound heuristics, the
    -- semantic verdict, outbound tool-call interceptions and the output scan.
    -- Without it "what did we decide for request X, and why" is unanswerable,
    -- and it is the natural idempotency key for the async anchoring worker.
    -- Cannot be backfilled, so it is NOT NULL from the start.
    request_id             UUID NOT NULL,

    direction              TEXT NOT NULL CHECK (direction IN ('INBOUND', 'OUTBOUND')),
    violation_source       TEXT NOT NULL REFERENCES violation_sources(source),
    llama_guard_code       TEXT,

    -- The durable record. content_preview is bounded so that the PII-containment
    -- this table is built around is enforced rather than merely intended: one
    -- caller passing the full content as the "preview" would otherwise defeat
    -- the whole retention design.
    content_sha256         CHAR(64) NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    content_preview        TEXT NOT NULL CHECK (length(content_preview) <= 512),

    -- Optional, and purged on a schedule. Null once expired.
    raw_content            TEXT,
    raw_content_expires_at TIMESTAMPTZ,

    applied_downgrade_from INT CHECK (applied_downgrade_from BETWEEN 0 AND 3),
    applied_downgrade_to   INT CHECK (applied_downgrade_to BETWEEN 0 AND 3),

    -- On-chain anchoring state. The async worker claims rows, records the
    -- transaction once a receipt confirms it, and counts attempts so a
    -- permanently failing row stops being retried forever.
    tx_hash                TEXT,
    anchored_at            TIMESTAMPTZ,
    anchor_attempts        INT NOT NULL DEFAULT 0 CHECK (anchor_attempts >= 0),

    metadata               JSONB,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The capability ratchet, enforced by the database as well as by Go.
    CONSTRAINT downgrade_is_ratchet CHECK (
        applied_downgrade_from IS NULL
        OR applied_downgrade_to IS NULL
        OR applied_downgrade_to >= applied_downgrade_from
    )
);

CREATE INDEX IF NOT EXISTS idx_violations_session ON guardrail_violations(session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_request ON guardrail_violations(request_id);

-- Retention sweeps and the anchoring worker both scan by time, and neither is
-- served by the session-scoped index above.
CREATE INDEX IF NOT EXISTS idx_violations_created ON guardrail_violations(created_at);

-- Rows still awaiting anchoring. Partial, so it stays small as the table grows.
CREATE INDEX IF NOT EXISTS idx_violations_unanchored
    ON guardrail_violations(created_at) WHERE anchored_at IS NULL;

-- Rows whose raw_content is due for purging.
CREATE INDEX IF NOT EXISTS idx_violations_expiring
    ON guardrail_violations(raw_content_expires_at) WHERE raw_content IS NOT NULL;

-- DEFAULT NOW() fires only on INSERT, so updated_at needs a trigger or it stays
-- permanently equal to created_at. clock_timestamp() rather than now() so it
-- advances even within a single transaction.
--
-- Note it does NOT touch risk_updated_at: that is the decay baseline and is
-- owned by the risk path alone.
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
-- Inherited tables (async overseer)
-- ---------------------------------------------------------------------------

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
