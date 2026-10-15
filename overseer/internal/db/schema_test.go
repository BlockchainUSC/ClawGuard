package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

// The migration applies cleanly to an empty database, and applying it twice is
// a no-op rather than an error.
func TestMigration_IsIdempotent(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	dbtest.ApplyMigration(t, ctx, pool) // second application
	dbtest.ApplyMigration(t, ctx, pool) // third, for good measure

	for _, table := range []string{"session_states", "guardrail_violations", "actions", "boundaries", "violations"} {
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
				   (session_id, direction, violation_source, content_sha256, content_preview)
				 VALUES ($1, $2, $3, repeat('a', 64), 'preview')`,
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
		   (session_id, direction, violation_source, content_sha256, content_preview,
		    applied_downgrade_from, applied_downgrade_to)
		 VALUES ($1, 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview', 2, 1)`, session)
	if err == nil {
		t.Error("a downgrade from tier 2 to tier 1 was accepted")
	}

	// The same values in the correct direction must be accepted.
	_, err = pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, content_sha256, content_preview,
		    applied_downgrade_from, applied_downgrade_to)
		 VALUES ($1, 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview', 1, 2)`, session)
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
		   (session_id, direction, violation_source, llama_guard_code,
		    content_sha256, content_preview, raw_content, metadata)
		 VALUES ($1, 'OUTBOUND', 'LLAMA_GUARD_3', 'S13', repeat('b', 64), 'redacted preview',
		         NULL, '{"latency_ms": 42}'::jsonb)`, session)
	if err != nil {
		t.Errorf("a violation row with raw_content NULL was rejected: %v", err)
	}

	// The hash and preview are not optional.
	_, err = pool.Exec(ctx,
		`INSERT INTO guardrail_violations (session_id, direction, violation_source, content_preview)
		 VALUES ($1, 'INBOUND', 'ENTROPY', 'preview')`, session)
	if err == nil {
		t.Error("a violation row without content_sha256 was accepted")
	}
}

func TestMigration_ViolationRequiresKnownSession(t *testing.T) {
	pool, ctx := dbtest.Pool(t)

	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, content_sha256, content_preview)
		 VALUES (gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('c', 64), 'preview')`)
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
			   (session_id, direction, violation_source, content_sha256, content_preview)
			 VALUES ($1, 'INBOUND', 'FAST_REGEX', $2, 'preview')`, session, bad)
		if err == nil {
			t.Errorf("content_sha256 = %q was accepted", bad)
		}
	}

	// Uppercase hex is also wrong: one content hash must have one spelling, or
	// deduplicating and joining on it quietly stops working.
	_, err := pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, 'INBOUND', 'FAST_REGEX', repeat('A', 64), 'preview')`, session)
	if err == nil {
		t.Error("an uppercase digest was accepted")
	}

	// A well-formed digest still works.
	_, err = pool.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, content_sha256, content_preview)
		 VALUES ($1, 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview')`, session)
	if err != nil {
		t.Errorf("a valid digest was rejected: %v", err)
	}
}
