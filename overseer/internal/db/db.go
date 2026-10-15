// Package db is the pgxpool wrapper for the async overseer's tables: actions,
// boundaries and violations.
//
// It belongs to the batch worker, not to the gateway. Gateway state lives in
// session_states and guardrail_violations and is reached through
// internal/session, which takes a *pgxpool.Pool directly — pass DB.Pool to it
// rather than opening a second pool.
package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ActionRecord struct {
	ID         int
	AgentID    string
	ActionType string
	Payload    []byte // JSONB stored as raw bytes
	Evaluated  bool
	CreatedAt  time.Time
}

type Boundary struct {
	ID        int
	AgentID   string
	Rule      string
	RuleHash  string
	Active    bool
	CreatedAt time.Time
}

type DB struct {
	Pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

func (d *DB) Close() {
	d.Pool.Close()
}

func (d *DB) GetUnevaluatedActions(ctx context.Context) ([]ActionRecord, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, agent_id, action_type, payload, evaluated, created_at
		 FROM actions
		 WHERE evaluated = false
		 ORDER BY created_at ASC
		 LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ActionRecord, error) {
		var a ActionRecord
		err := row.Scan(&a.ID, &a.AgentID, &a.ActionType, &a.Payload, &a.Evaluated, &a.CreatedAt)
		return a, err
	})
}

func (d *DB) GetActiveBoundaries(ctx context.Context, agentID string) ([]Boundary, error) {
	rows, err := d.Pool.Query(ctx,
		`SELECT id, agent_id, rule, rule_hash, active, created_at
		 FROM boundaries
		 WHERE agent_id = $1 AND active = true`,
		agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Boundary, error) {
		var b Boundary
		err := row.Scan(&b.ID, &b.AgentID, &b.Rule, &b.RuleHash, &b.Active, &b.CreatedAt)
		return b, err
	})
}

func (d *DB) MarkEvaluated(ctx context.Context, actionID int) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE actions SET evaluated = true WHERE id = $1`,
		actionID)
	return err
}

func (d *DB) InsertViolation(ctx context.Context, agentID string, actionID int, boundaryID int, reason string, severity string) error {
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO violations (agent_id, action_id, boundary_id, severity, reasoning)
		 VALUES ($1, $2, $3, $4, $5)`,
		agentID, actionID, boundaryID, severity, reason)
	return err
}
