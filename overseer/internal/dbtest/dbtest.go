// Package dbtest provides a throwaway PostgreSQL schema for tests.
//
// Like net/http/httptest, this is a helper package that imports testing: it is
// only ever used from _test.go files.
//
// Each call to Pool creates its own schema, applies the migration into it, and
// drops it on cleanup. Tests never see each other's rows and never touch
// application tables.
//
// This is the only place that knows how a test database is built. Phases 3-8
// add more tables and more tests against them; a second harness alongside this
// one is how the two drift apart until a test passes against a schema the
// application never has.
package dbtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

const (
	DSNEnv     = "TEST_POSTGRES_DSN"
	RequireEnv = "REQUIRE_DB_TESTS"
)

var loadOnce sync.Once

// LoadDotEnv walks up from the working directory to find a .env, so the DSN
// does not need exporting in every shell. Already-set variables win.
//
// go test runs each binary with its own package directory as the working
// directory, so a .env beside the test is found first and a repo-root .env is
// found by walking up. Pool calls this itself; it is exported for the test that
// asserts the lookup actually finds something, because a DSN that silently
// stays empty skips every database test while the suite still reports "ok".
func LoadDotEnv() {
	loadOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			return
		}
		for {
			if candidate := filepath.Join(dir, ".env"); fileExists(candidate) {
				_ = godotenv.Load(candidate)
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return // reached the filesystem root
			}
			dir = parent
		}
	})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// repoRoot walks up until it finds the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if fileExists(filepath.Join(dir, "go.mod")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the working directory")
		}
		dir = parent
	}
}

// Pool returns a connection pool bound to a fresh, isolated schema with the
// migration already applied.
//
// Skips when TEST_POSTGRES_DSN is unset — unless REQUIRE_DB_TESTS is set, in
// which case it fails. A skipped test prints "ok", which is indistinguishable
// from a pass, so there has to be a way to demand the real thing.
func Pool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	LoadDotEnv()

	dsn := os.Getenv(DSNEnv)
	if dsn == "" {
		if os.Getenv(RequireEnv) != "" {
			t.Fatalf("%s is set but %s is not: refusing to silently skip database tests", RequireEnv, DSNEnv)
		}
		t.Skipf("%s not set; skipping database tests (set %s=1 to make this a failure)", DSNEnv, RequireEnv)
	}

	ctx := context.Background()
	schema := fmt.Sprintf("guard_test_%d", time.Now().UnixNano())

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parsing %s: %v", DSNEnv, err)
	}
	// Every connection in the pool lands in the throwaway schema, and the
	// migration script is multi-statement so it needs the simple protocol.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("creating schema: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatalf("connecting to schema: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		admin.Close()
	})

	ApplyMigration(t, ctx, pool)

	return pool, ctx
}

// ApplyMigration applies migrations/0001_init.sql into whatever schema pool is
// bound to. Pool calls it once; it is exported for the test that re-applies the
// migration to prove it is idempotent, which is the property the hand-written
// guards in that file exist to preserve.
func ApplyMigration(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	path := filepath.Join(repoRoot(t), "migrations", "0001_init.sql")
	migration, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading migration %s: %v", path, err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("applying migration: %v", err)
	}
}
