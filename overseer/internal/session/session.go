// Package session owns the durable half of the capability model: which tier a
// session currently holds, how much risk it has accumulated, and the record of
// why.
//
// The capability package decides. This package remembers.
package session

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"openclaw/oversight/overseer/internal/auth"
	"openclaw/oversight/overseer/internal/capability"
)

// ErrSessionNotOwned means the session exists but belongs to a different user.
//
// It is kept separate from "no such session" so LoadOrCreate knows not to try
// creating it. Callers must NOT pass that distinction on to the client: an
// endpoint that answers "wrong owner" differently from "never existed" tells an
// attacker which session ids are real. Both must produce the same response.
var ErrSessionNotOwned = errors.New("session: belongs to a different user")

// Session is one row of session_states.
type Session struct {
	ID        uuid.UUID
	UserID    string
	Tier      capability.Tier
	RiskScore int
	CreatedAt time.Time
	UpdatedAt time.Time

	// IdentityVerified carries auth.User.Verified forward, so the audit trail
	// records how much the identity behind this reputation was worth.
	IdentityVerified bool
}

// NewID mints a session identifier.
//
// Server-issued, deliberately. If clients chose their own, a quarantined user
// would simply send a different one and start again at tier 0, and the whole
// ratchet would be decoration.
func NewID() uuid.UUID { return uuid.New() }

// Direction matches the CHECK constraint on guardrail_violations.direction.
type Direction string

const (
	Inbound  Direction = "INBOUND"
	Outbound Direction = "OUTBOUND"
)

// Violation is one row of guardrail_violations: the evidence behind a decision.
type Violation struct {
	Direction      Direction
	Source         capability.Source
	LlamaGuardCode string

	// ContentSHA256 and ContentPreview are the durable record. RawContent is
	// optional and subject to the retention window — see the schema comments on
	// why the offending text is not simply stored forever.
	ContentSHA256  string
	ContentPreview string
	RawContent     *string

	Metadata []byte // JSON, or nil
}

// Store is the persistence boundary. The gateway depends on this interface, so
// the session logic can be tested without reasoning about SQL.
type Store interface {
	// LoadOrCreate returns the session for id, creating it if it does not exist.
	//
	// A new session does not start at tier 0. It inherits the most restrictive
	// recent tier recorded for the same user, which is what stops a demoted
	// user from reconnecting into a clean slate.
	LoadOrCreate(ctx context.Context, id uuid.UUID, user auth.User) (Session, error)

	// Apply persists a decision and its evidence together, atomically, and
	// returns the session as it now stands.
	//
	// Together is the point. A demotion written without its violations is an
	// unexplained punishment; violations written without the demotion is an
	// observation nobody acted on. Either alone is worse than neither.
	Apply(ctx context.Context, s Session, d capability.Decision, vs []Violation) (Session, error)
}
