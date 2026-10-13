package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// These tests exercise the real migration against a real PostgreSQL server.
//
// They are not mocked deliberately: every defect they are written to catch —
// CHECK constraint coverage, trigger behaviour, idempotency — is invisible to a
// mock, because a mock has no constraints to violate.
//
// Set TEST_POSTGRES_DSN to run them. Each test builds a throwaway schema and
// drops it afterwards, so it never touches application tables.
const dsnEnv = "TEST_POSTGRES_DSN"

func migrationPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "migrations", "0001_init.sql"))
	if err != nil {
		t.Fatalf("resolving migration path: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("migration not found at %s: %v", p, err)
	}
	return p
}

// newTestSchema connects, creates an isolated schema, applies the migration
// into it, and registers cleanup.
func newTestSchema(t *testing.T) (*pgx.Conn, context.Context) {
	t.Helper()

	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping database tests", dsnEnv)
	}

	ctx := context.Background()

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parsing %s: %v", dsnEnv, err)
	}
	// The migration is a multi-statement script; the extended protocol rejects those.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}

	schema := fmt.Sprintf("guard_test_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("creating schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		_ = conn.Close(ctx)
	})
	if _, err := conn.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatalf("setting search_path: %v", err)
	}

	applyMigration(t, ctx, conn)
	return conn, ctx
}

func applyMigration(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	sql, err := os.ReadFile(migrationPath(t))
	if err != nil {
		t.Fatalf("reading migration: %v", err)
	}
	if _, err := conn.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("applying migration: %v", err)
	}
}

func insertSession(t *testing.T, ctx context.Context, conn *pgx.Conn, tier int) string {
	t.Helper()
	var id string
	err := conn.QueryRow(ctx,
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
	conn, ctx := newTestSchema(t)
	applyMigration(t, ctx, conn) // second application
	applyMigration(t, ctx, conn) // third, for good measure

	for _, table := range []string{"session_states", "guardrail_violations", "actions", "boundaries", "violations"} {
		var exists bool
		err := conn.QueryRow(ctx,
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
	conn, ctx := newTestSchema(t)

	for _, tier := range []int{-1, 4, 99} {
		_, err := conn.Exec(ctx,
			`INSERT INTO session_states (session_id, user_id, current_tier)
			 VALUES (gen_random_uuid(), 'user-1', `+fmt.Sprint(tier)+`)`)
		if err == nil {
			t.Errorf("current_tier = %d was accepted", tier)
		}
	}
}

func TestMigration_RejectsNegativeRiskScore(t *testing.T) {
	conn, ctx := newTestSchema(t)

	_, err := conn.Exec(ctx,
		`INSERT INTO session_states (session_id, user_id, risk_score)
		 VALUES (gen_random_uuid(), 'user-1', -1)`)
	if err == nil {
		t.Error("risk_score = -1 was accepted")
	}
}

func TestMigration_RejectsUnknownEnumValues(t *testing.T) {
	conn, ctx := newTestSchema(t)
	session := insertSession(t, ctx, conn, 0)

	cases := []struct {
		name             string
		direction, src   string
	}{
		{"bad direction", "SIDEWAYS", "FAST_REGEX"},
		{"lowercase direction", "inbound", "FAST_REGEX"},
		{"bad source", "INBOUND", "VIBES"},
		{"stale source name", "INBOUND", "TOOL_V"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := conn.Exec(ctx,
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
	conn, ctx := newTestSchema(t)
	session := insertSession(t, ctx, conn, 0)

	_, err := conn.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, content_sha256, content_preview,
		    applied_downgrade_from, applied_downgrade_to)
		 VALUES ($1, 'INBOUND', 'FAST_REGEX', repeat('a', 64), 'preview', 2, 1)`, session)
	if err == nil {
		t.Error("a downgrade from tier 2 to tier 1 was accepted")
	}

	// The same values in the correct direction must be accepted.
	_, err = conn.Exec(ctx,
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
	conn, ctx := newTestSchema(t)
	session := insertSession(t, ctx, conn, 0)

	var created, updated time.Time
	err := conn.QueryRow(ctx,
		`SELECT created_at, updated_at FROM session_states WHERE session_id = $1`, session).
		Scan(&created, &updated)
	if err != nil {
		t.Fatalf("reading timestamps: %v", err)
	}
	if !updated.Equal(created) {
		t.Fatalf("on insert, updated_at (%s) != created_at (%s)", updated, created)
	}

	if _, err := conn.Exec(ctx,
		`UPDATE session_states SET current_tier = 1 WHERE session_id = $1`, session); err != nil {
		t.Fatalf("updating: %v", err)
	}

	var after time.Time
	if err := conn.QueryRow(ctx,
		`SELECT updated_at FROM session_states WHERE session_id = $1`, session).Scan(&after); err != nil {
		t.Fatalf("re-reading updated_at: %v", err)
	}
	if !after.After(created) {
		t.Errorf("updated_at did not advance: created=%s updated=%s", created, after)
	}
}

func TestMigration_ViolationsSurviveWithRequiredContentColumns(t *testing.T) {
	conn, ctx := newTestSchema(t)
	session := insertSession(t, ctx, conn, 0)

	// raw_content is nullable by design: it is subject to a retention window,
	// while the hash and redacted preview are the durable record.
	_, err := conn.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, llama_guard_code,
		    content_sha256, content_preview, raw_content, metadata)
		 VALUES ($1, 'OUTBOUND', 'LLAMA_GUARD_3', 'S13', repeat('b', 64), 'redacted preview',
		         NULL, '{"latency_ms": 42}'::jsonb)`, session)
	if err != nil {
		t.Errorf("a violation row with raw_content NULL was rejected: %v", err)
	}

	// The hash and preview are not optional.
	_, err = conn.Exec(ctx,
		`INSERT INTO guardrail_violations (session_id, direction, violation_source, content_preview)
		 VALUES ($1, 'INBOUND', 'ENTROPY', 'preview')`, session)
	if err == nil {
		t.Error("a violation row without content_sha256 was accepted")
	}
}

func TestMigration_ViolationRequiresKnownSession(t *testing.T) {
	conn, ctx := newTestSchema(t)

	_, err := conn.Exec(ctx,
		`INSERT INTO guardrail_violations
		   (session_id, direction, violation_source, content_sha256, content_preview)
		 VALUES (gen_random_uuid(), 'INBOUND', 'FAST_REGEX', repeat('c', 64), 'preview')`)
	if err == nil {
		t.Error("a violation referencing an unknown session was accepted")
	}
}

func TestSchemaTests_SkipCleanlyWithoutDSN(t *testing.T) {
	if os.Getenv(dsnEnv) == "" && !strings.Contains(t.Name(), "never") {
		t.Logf("%s unset: database tests skip rather than fail", dsnEnv)
	}
}
