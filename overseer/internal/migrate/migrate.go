// Package migrate applies the SQL files in migrations/ in order, once each.
//
// It exists because migrations stop being re-runnable the moment they contain
// ALTER. CREATE TABLE IF NOT EXISTS can be applied a hundred times; ALTER TABLE
// ADD COLUMN fails the second time. The schema file comments already carry one
// hand-written DO $$ guard working around exactly this, and that approach does
// not survive a third or fourth migration.
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Conn is satisfied by *pgx.Conn, *pgxpool.Pool and pgx.Tx, so the runner works
// from a command, from a test harness, or inside a transaction.
type Conn interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const ledgerDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT        PRIMARY KEY,
    checksum    CHAR(64)    NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// Migration is one file on disk.
type Migration struct {
	Version  string // the filename, e.g. "0001_init.sql"
	SQL      string
	Checksum string
}

// Load reads and sorts every .sql file in dir. Lexical order is the apply
// order, which is why the files are zero-padded.
func Load(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{
			Version:  e.Name(),
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Apply runs every migration that has not been applied yet, in order, and
// records it. Returns the versions it applied.
//
// A migration whose contents changed since it was applied is an error, not a
// warning: the database no longer matches the file, and silently continuing
// means every later assumption about the schema is unverified.
func Apply(ctx context.Context, conn Conn, dir string) ([]string, error) {
	migrations, err := Load(dir)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, ledgerDDL); err != nil {
		return nil, fmt.Errorf("creating schema_migrations: %w", err)
	}

	var applied []string
	for _, m := range migrations {
		var recorded string
		err := conn.QueryRow(ctx,
			`SELECT checksum FROM schema_migrations WHERE version = $1`, m.Version).Scan(&recorded)

		switch {
		case err == nil && recorded == m.Checksum:
			continue // already applied, unchanged
		case err == nil:
			return applied, fmt.Errorf(
				"%s was already applied but its contents have changed "+
					"(recorded %s…, file is %s…): write a new migration instead of editing an applied one",
				m.Version, recorded[:8], m.Checksum[:8])
		case !isNoRows(err):
			return applied, fmt.Errorf("checking %s: %w", m.Version, err)
		}

		if _, err := conn.Exec(ctx, m.SQL); err != nil {
			return applied, fmt.Errorf("applying %s: %w", m.Version, err)
		}
		if _, err := conn.Exec(ctx,
			`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`,
			m.Version, m.Checksum); err != nil {
			return applied, fmt.Errorf("recording %s: %w", m.Version, err)
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// Pending reports which migrations have not been applied yet, without applying
// them. Useful as a CI gate: a deploy whose schema is behind should fail loudly
// rather than start and misbehave.
func Pending(ctx context.Context, conn Conn, dir string) ([]string, error) {
	migrations, err := Load(dir)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, ledgerDDL); err != nil {
		return nil, fmt.Errorf("creating schema_migrations: %w", err)
	}

	var pending []string
	for _, m := range migrations {
		var recorded string
		err := conn.QueryRow(ctx,
			`SELECT checksum FROM schema_migrations WHERE version = $1`, m.Version).Scan(&recorded)
		switch {
		case isNoRows(err):
			pending = append(pending, m.Version)
		case err != nil:
			return nil, fmt.Errorf("checking %s: %w", m.Version, err)
		case recorded != m.Checksum:
			return nil, fmt.Errorf("%s was applied but has since been edited", m.Version)
		}
	}
	return pending, nil
}
