package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"openclaw/oversight/overseer/internal/capability"
	"openclaw/oversight/overseer/internal/dbtest"
)

// These tests exercise the real migration against a real PostgreSQL server.
//
// They are not mocked deliberately: every defect they are written to catch —
// CHECK constraint coverage, trigger behaviour, idempotency — is invisible to a
// mock, because a mock has no constraints to violate.
//
// Set TEST_POSTGRES_DSN to run them. dbtest.Pool builds a throwaway schema per
// test and drops it afterwards, so they never touch application tables.

func insertSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tier int) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO session_states (session_id, user_id, current_tier)
		 VALUES (gen_random_uuid(), 'user-1', `+fmt.Sprint(tier)+`)
		 RETURNING session_id`).Scan(&id)
	if err != nil {
		t.Fatalf("inserting session: %v", err)
	}
	return id
}

// The migrations produce the expected schema, and re-running the runner is a
// no-op rather than an error.
//
// Idempotency used to be a property of the SQL itself (every statement was
// CREATE ... IF NOT EXISTS). It is now a property of the runner's ledger, which
// is what lets a migration contain ALTER. The runner's own behaviour is tested
// in internal/migrate; this checks the result.
func TestMigration_ProducesTheExpectedSchema(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	dbtest.ApplyMigration(t, ctx, pool) // second call: must not error

	for _, table := range []string{
		"session_states", "guardrail_violations", "violation_sources",
		"actions", "boundaries", "violations", "schema_migrations",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables
			                WHERE table_schema = current_schema() AND table_name = $1)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("checking %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s was not created", table)
		}
	}
}

// Enumerated columns must be constrained in the database. The one defect
// already shipped in this repo is a vocabulary mismatch between Go and a CHECK
// constraint, which is exactly the class of bug these assertions catch.
func TestMigration_RejectsOutOfRangeTier(t *testing.T) {
	pool, ctx := dbtest.Pool(t)

	for _, tier := range []int{-1, 4, 99} {
		_, err := pool.Exec(ctx,
			`INSERT INTO session_states (session_id, user_id, current_tier)
			 VALUES (gen_random_uuid(), 'user-1', `+fmt.Sprint(tier)+`)`)
		if err == nil {
			t.Errorf("current_tier = %d was accepted", tier)
		}
	}
}

func TestMigration_RejectsNegativeRiskScore(t *testing.T) {
	pool, ctx := dbtest.Pool(t)

	_, err := pool.Exec(ctx,
		`INSERT INTO session_states (session_id, user_id, risk_score)
		 VALUES (gen_random_uuid(), 'user-1', -1)`)
	if err == nil {
		t.Error("risk_score = -1 was accepted")
	}
}

func TestMigration_RejectsUnknownEnumValues(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	cases := []struct {
		name           string
		direction, src string
	}{
		{"bad direction", "SIDEWAYS", "FAST_REGEX"},
		{"lowercase direction", "inbound", "FAST_REGEX"},
		{"bad source", "INBOUND", "VIBES"},
		{"stale source name", "INBOUND", "TOOL_V"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := pool.Exec(ctx,
				`INSERT INTO guardrail_violations
				   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
				 VALUES ($1, gen_random_uuid(), $2, $3, repeat('a', 64), 'preview')`,
				session, c.direction, c.src)
			if err == nil {
				t.Errorf("direction=%q source=%q was accepted", c.direction, c.src)
			}
		})
	}
}

// The capability ratchet is enforced by the database as well as by Go: a
// recorded downgrade can never restore capability.
func TestMigration_RejectsUpgradeRecordedAsDowngrade(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview,
		    applied_downgrade_from, applied_downgrade_to)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview', 2, 1)`, session)
	if err == nil {
		t.Error("a downgrade from tier 2 to tier 1 was accepted")
	}

	// The same values in the correct direction must be accepted.
	_, err = pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview,
		    applied_downgrade_from, applied_downgrade_to)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview', 1, 2)`, session)
	if err != nil {
		t.Errorf("a legitimate downgrade 1 -> 2 was rejected: %v", err)
	}
}

// DEFAULT NOW() fires only on INSERT. Without the trigger, updated_at would
// stay equal to created_at forever and every staleness check built on it would
// silently never fire.
func TestMigration_UpdatedAtAdvancesOnUpdate(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	var created, updated time.Time
	err := pool.QueryRow(ctx,
		`SELECT created_at, updated_at FROM session_states WHERE session_id = $1`, session).
		Scan(&created, &updated)
	if err != nil {
		t.Fatalf("reading timestamps: %v", err)
	}
	if !updated.Equal(created) {
		t.Fatalf("on insert, updated_at (%s) != created_at (%s)", updated, created)
	}

	if _, err := pool.Exec(ctx,
		`UPDATE session_states SET current_tier = 1 WHERE session_id = $1`, session); err != nil {
		t.Fatalf("updating: %v", err)
	}

	var after time.Time
	if err := pool.QueryRow(ctx,
		`SELECT updated_at FROM session_states WHERE session_id = $1`, session).Scan(&after); err != nil {
		t.Fatalf("re-reading updated_at: %v", err)
	}
	if !after.After(created) {
		t.Errorf("updated_at did not advance: created=%s updated=%s", created, after)
	}
}

func TestMigration_ViolationsSurviveWithRequiredContentColumns(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	// raw_content is nullable by design: it is subject to a retention window,
	// while the hash and redacted preview are the durable record.
	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, llama_guard_code,
		    content_sha256, content_preview, raw_content, metadata)
		 VALUES ($1, gen_random_uuid(), 'OUTBOUND', 'LLAMA_GUARD_3', 'S13', repeat('b', 64), 'redacted preview',
		         NULL, '{"latency_ms": 42}'::jsonb)`, session)
	if err != nil {
		t.Errorf("a violation row with raw_content NULL was rejected: %v", err)
	}

	// The hash and preview are not optional.
	_, err = pool.Exec(ctx,
		`INSERT INTO guardrail_violations (session_id, request_id, direction, violation_source, content_preview)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'ENTROPY', 'preview')`, session)
	if err == nil {
		t.Error("a violation row without content_sha256 was accepted")
	}
}

func TestMigration_ViolationRequiresKnownSession(t *testing.T) {
	pool, ctx := dbtest.Pool(t)

	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
		 VALUES (gen_random_uuid(), gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('c', 64), 'preview')`)
	if err == nil {
		t.Error("a violation referencing an unknown session was accepted")
	}
}

// The .env lookup must actually find a file, otherwise the DSN silently stays
// empty and every database test skips while the suite still reports "ok".
func TestDotEnvIsDiscoverable(t *testing.T) {
	dbtest.LoadDotEnv()
	if os.Getenv(dbtest.DSNEnv) == "" && os.Getenv(dbtest.RequireEnv) == "" {
		t.Skipf("no %s in the environment or any .env file from here to the filesystem root", dbtest.DSNEnv)
	}
	if os.Getenv(dbtest.DSNEnv) == "" {
		t.Fatalf("%s is set but no %s was found in the environment or any .env file",
			dbtest.RequireEnv, dbtest.DSNEnv)
	}
}

// content_sha256 is the durable record once raw_content ages out of retention,
// so a truncated or empty digest silently destroys the audit trail. CHAR(64)
// alone does not prevent that: it pads and accepts anything.
func TestMigration_RejectsMalformedContentHash(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	for _, bad := range []string{"", "abc", "ZZ", "NOT-A-HASH"} {
		_, err := pool.Exec(ctx,
			`INSERT INTO guardrail_violations
			   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
			 VALUES ($1, gen_random_uuid(), 'INBOUND', 'FAST_REGEX', $2, 'preview')`, session, bad)
		if err == nil {
			t.Errorf("content_sha256 = %q was accepted", bad)
		}
	}

	// Uppercase hex is also wrong: one content hash must have one spelling, or
	// deduplicating and joining on it quietly stops working.
	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('A', 64), 'preview')`, session)
	if err == nil {
		t.Error("an uppercase digest was accepted")
	}

	// A well-formed digest still works.
	_, err = pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview')`, session)
	if err != nil {
		t.Errorf("a valid digest was rejected: %v", err)
	}
}

// capability.Source constants and the violation_sources table are two hand-
// maintained copies of one vocabulary. Nothing stops them drifting except this.
//
// Drift is quiet in the dangerous direction: a Go constant with no row fails
// the foreign key at insert time, which means an inspection layer silently
// cannot record anything it detects.
func TestViolationSources_MatchTheGoConstants(t *testing.T) {
	pool, ctx := dbtest.Pool(t)

	inGo := []capability.Source{
		capability.SourceFastRegex,
		capability.SourceEntropy,
		capability.SourceTokenSpike,
		capability.SourceLlamaGuard,
		capability.SourceToolValidator,
	}

	for _, src := range inGo {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM violation_sources WHERE source = $1)`, string(src),
		).Scan(&exists); err != nil {
			t.Fatalf("checking %s: %v", src, err)
		}
		if !exists {
			t.Errorf("capability.Source %q has no row in violation_sources; "+
				"any violation from that layer would fail its foreign key", src)
		}
	}

	// And nothing in the table that Go cannot produce.
	rows, err := pool.Query(ctx, `SELECT source FROM violation_sources`)
	if err != nil {
		t.Fatalf("listing sources: %v", err)
	}
	defer rows.Close()
	known := make(map[string]bool, len(inGo))
	for _, s := range inGo {
		known[string(s)] = true
	}
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		if !known[src] {
			t.Errorf("violation_sources has %q with no matching capability.Source constant", src)
		}
	}
}

// An unknown source must be rejected by the foreign key, exactly as the old
// CHECK constraint did. Moving to a lookup table must not have loosened this.
func TestViolationSources_RejectUnknownSource(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'VIBES', repeat('a', 64), 'preview')`, session)
	if err == nil {
		t.Error("an unknown violation_source was accepted")
	}
}

// request_id cannot be backfilled, which is why it is NOT NULL from the start.
// Without it, phase 6 cannot correlate the inbound signals, the tool-call
// interceptions and the output scan belonging to one turn.
func TestMigration_RequiresRequestID(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview')`, session)
	if err == nil {
		t.Error("a violation without a request_id was accepted")
	}
}

// content_preview is bounded so the PII containment this table is built around
// is enforced rather than merely intended. One caller passing the full content
// as the "preview" would otherwise defeat the entire retention design.
func TestMigration_BoundsContentPreview(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	session := insertSession(t, ctx, pool, 0)

	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('a', 64), repeat('x', 513))`, session)
	if err == nil {
		t.Error("a 513-character preview was accepted; the bound is not enforced")
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, request_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('a', 64), repeat('x', 512))`, session)
	if err != nil {
		t.Errorf("a 512-character preview was rejected: %v", err)
	}
}
