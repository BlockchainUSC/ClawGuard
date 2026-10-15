package migrate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openclaw/oversight/overseer/internal/dbtest"
	"openclaw/oversight/overseer/internal/migrate"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// The point of the runner: a migration containing ALTER runs exactly once.
func TestApply_RunsEachMigrationOnce(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	dir := t.TempDir()

	// ADD COLUMN is not idempotent; a second run would error.
	write(t, dir, "0001_a.sql", `CREATE TABLE widgets (id INT PRIMARY KEY);`)
	write(t, dir, "0002_b.sql", `ALTER TABLE widgets ADD COLUMN label TEXT;`)

	applied, err := migrate.Apply(ctx, pool, dir)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied %v, want both", applied)
	}

	again, err := migrate.Apply(ctx, pool, dir)
	if err != nil {
		t.Fatalf("second apply: %v (the ALTER ran twice)", err)
	}
	if len(again) != 0 {
		t.Errorf("second apply re-ran %v", again)
	}
}

// Order matters: 0002 depends on the table 0001 creates.
func TestApply_RunsInLexicalOrder(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	dir := t.TempDir()

	write(t, dir, "0002_second.sql", `ALTER TABLE ordered ADD COLUMN b TEXT;`)
	write(t, dir, "0001_first.sql", `CREATE TABLE ordered (a INT);`)

	applied, err := migrate.Apply(ctx, pool, dir)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(applied) != 2 || applied[0] != "0001_first.sql" {
		t.Errorf("applied %v, want 0001 first", applied)
	}
}

// Editing a migration that has already run means the database no longer matches
// the file. Continuing silently would leave every later assumption unverified.
func TestApply_RefusesAnEditedMigration(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	dir := t.TempDir()

	write(t, dir, "0001_a.sql", `CREATE TABLE edited (id INT);`)
	if _, err := migrate.Apply(ctx, pool, dir); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	write(t, dir, "0001_a.sql", `CREATE TABLE edited (id INT, extra TEXT);`)
	_, err := migrate.Apply(ctx, pool, dir)
	if err == nil {
		t.Fatal("an edited migration was re-accepted")
	}
	if !strings.Contains(err.Error(), "contents have changed") {
		t.Errorf("error %q does not explain what happened", err)
	}
}

func TestPending_ListsWithoutApplying(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	dir := t.TempDir()
	write(t, dir, "0001_a.sql", `CREATE TABLE pending_check (id INT);`)

	pending, err := migrate.Pending(ctx, pool, dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %v, want one", pending)
	}

	// Pending must not have applied it.
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema = current_schema() AND table_name = 'pending_check')`,
	).Scan(&exists); err != nil {
		t.Fatalf("checking: %v", err)
	}
	if exists {
		t.Error("Pending applied the migration it was only asked to list")
	}
}

// The real migrations must apply to an empty database and leave nothing pending.
func TestApply_RealMigrationsAreComplete(t *testing.T) {
	pool, ctx := dbtest.Pool(t) // already applies them
	wd, _ := os.Getwd()
	dir := filepath.Join(wd, "..", "..", "..", "migrations")

	pending, err := migrate.Pending(ctx, pool, dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("after dbtest applied them, still pending: %v", pending)
	}
}
