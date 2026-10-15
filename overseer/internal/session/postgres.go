package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"openclaw/guard/overseer/internal/auth"
	"openclaw/guard/overseer/internal/capability"
)

// PostgresStore implements Store against session_states and
// guardrail_violations.
type PostgresStore struct {
	pool   *pgxpool.Pool
	policy capability.Policy
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return NewPostgresStoreWithPolicy(pool, capability.DefaultPolicy())
}

// NewPostgresStoreWithPolicy is for callers that tune the risk policy. The
// store needs the half-life because it recomputes decay itself when saving, and
// that calculation has to match the one the engine used when deciding.
func NewPostgresStoreWithPolicy(pool *pgxpool.Pool, policy capability.Policy) *PostgresStore {
	return &PostgresStore{pool: pool, policy: policy}
}

var _ Store = (*PostgresStore)(nil)

// carryForwardWindow is how far back a user's history follows them into a new
// session. Too short and the ratchet is bypassable by reconnecting; too long
// and one bad afternoon shadows someone for a week. There is no correct value,
// only a documented one.
const carryForwardWindow = "24 hours"

// sessionColumns is listed once so the SELECT and the Scan cannot drift apart.
const sessionColumns = `session_id, user_id, current_tier, risk_score, created_at, updated_at`

// LoadOrCreate implements Store.LoadOrCreate; see that interface for what the
// behaviour is for. The comments below are about how it is achieved here.
func (s *PostgresStore) LoadOrCreate(ctx context.Context, id uuid.UUID, user auth.User) (Session, error) {
	// 1. The common case by far: the session already exists.
	sess, err := s.loadByID(ctx, id, user)
	switch {
	case err == nil:
		return sess, nil
	case errors.Is(err, ErrSessionNotOwned):
		// Stop here. Falling through to the create path would hit
		// ON CONFLICT DO NOTHING and then hand back the other user's row.
		return Session{}, err
	case !errors.Is(err, pgx.ErrNoRows):
		// A real failure, not "no such session". Returning here is what keeps a
		// database outage from yielding a zero-valued Session — whose Tier would
		// be TierFull, i.e. unrestricted. Every error that is not ErrNoRows must
		// leave through this branch.
		return Session{}, fmt.Errorf("loading session %s: %w", id, err)
	}

	// 2. Genuinely new. Find what this user carries with them.
	tier, risk, err := s.carryForward(ctx, user.ID)
	if err != nil {
		return Session{}, fmt.Errorf("carry-forward for %q: %w", user.ID, err)
	}

	// 3. Create it. ON CONFLICT DO NOTHING absorbs the race where two concurrent
	//    first requests for the same session id both reach this line: the loser's
	//    insert quietly does nothing instead of erroring on the primary key.
	_, err = s.pool.Exec(ctx, `
		INSERT INTO session_states (session_id, user_id, current_tier, risk_score)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (session_id) DO NOTHING`,
		id, user.ID, int(tier), risk)
	if err != nil {
		return Session{}, fmt.Errorf("creating session %s: %w", id, err)
	}

	// 4. Read it back rather than assembling a Session in Go from what we just
	//    sent. The database owns created_at and updated_at, and if a concurrent
	//    insert won the race this returns *their* row — so both callers agree on
	//    the session instead of each believing its own version.
	sess, err = s.loadByID(ctx, id, user)
	if err != nil {
		return Session{}, fmt.Errorf("reloading session %s after create: %w", id, err)
	}
	return sess, nil
}

// loadByID reads one session. It returns pgx.ErrNoRows unwrapped, because
// LoadOrCreate needs to tell "absent" apart from "broken".
func (s *PostgresStore) loadByID(ctx context.Context, id uuid.UUID, user auth.User) (Session, error) {
	var (
		sess Session
		tier int
	)

	err := s.pool.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM session_states WHERE session_id = $1`, id,
	).Scan(&sess.ID, &sess.UserID, &tier, &sess.RiskScore, &sess.CreatedAt, &sess.UpdatedAt)
	if err != nil {
		return Session{}, err
	}

	// ParseTier, never a capability.Tier(x) cast. A corrupt 7 in the column
	// becomes TierBlocked plus an error, rather than a Tier no profile matches.
	sess.Tier, err = capability.ParseTier(tier)
	if err != nil {
		return Session{}, fmt.Errorf("session %s: %w", id, err)
	}

	// The session id alone is not authorisation. Without this check, anyone
	// holding someone else's session id inherits that session: a user blocked
	// at tier 3 presents a colleague's id and is served at tier 0, and every
	// violation they then trigger is filed under the colleague's name.
	//
	// Verifying who the caller is (the auth package) is worth nothing if the
	// answer is never used.
	if sess.UserID != user.ID {
		return Session{}, ErrSessionNotOwned
	}

	// Deliberately not read from the database: Verified describes how *this
	// request* authenticated, not a property of the session. Two requests on one
	// session can authenticate differently once more than one scheme exists.
	sess.IdentityVerified = user.Verified

	return sess, nil
}

// carryForward returns the risk this user currently carries, and the tier that
// risk justifies, for a session they are opening now.
//
// It carries RISK, not tier. Carrying the tier directly makes a demotion
// permanent: each new session stamps a fresh updated_at, so the window slides
// forward every time the user returns, and nothing anywhere lowers a tier. One
// minute of inference downtime would quarantine a daily user for life.
//
// Risk decays, so a tier derived from it recovers on its own. The ratchet still
// holds strictly within a single session, which is the guarantee this project
// actually makes; it was never meant to span a user's whole history.
//
// Each candidate row is decayed from its own risk_updated_at before the worst
// is taken, rather than taking MAX() in SQL. Two independent maxima could
// describe a state that never existed, and a raw maximum ignores how long ago
// the risk was earned — which is the entire point.
func (s *PostgresStore) carryForward(ctx context.Context, userID string) (capability.Tier, int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT risk_score, risk_updated_at, now()
		  FROM session_states
		 WHERE user_id = $1
		   AND updated_at > now() - $2::interval`,
		userID, carryForwardWindow)
	if err != nil {
		return capability.TierBlocked, 0, err
	}
	defer rows.Close()

	worst := 0
	for rows.Next() {
		var (
			risk          int
			riskAt, dbNow time.Time
		)
		if err := rows.Scan(&risk, &riskAt, &dbNow); err != nil {
			return capability.TierBlocked, 0, err
		}
		if decayed := capability.Decay(risk, riskAt, dbNow, s.policy.HalfLife); decayed > worst {
			worst = decayed
		}
	}
	if err := rows.Err(); err != nil {
		return capability.TierBlocked, 0, err
	}

	return s.policy.Thresholds.TierFor(worst), worst, nil
}

// Apply implements Store.Apply; see that interface for why the decision and its
// evidence must land together. Here that is one transaction.
//
// The decision was computed from a session read at some earlier moment, which
// may since have changed. Everything below re-derives from the locked row
// rather than trusting the struct it was handed.
func (s *PostgresStore) Apply(ctx context.Context, sess Session, requestID uuid.UUID, d capability.Decision, vs []Violation) (Session, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Session{}, fmt.Errorf("begin: %w", err)
	}
	// Harmless after a successful Commit, and the thing that saves every early
	// return below from leaving a half-written transaction open.
	defer func() { _ = tx.Rollback(ctx) }()

	// FOR UPDATE holds the row until this transaction ends. Without it, two
	// concurrent demotions both read the old tier, both compute a result from
	// it, and the second write silently erases the first — leaving the session
	// at whichever committed last rather than at the stricter of the two.
	// risk_updated_at, not updated_at. The trigger advances updated_at on every
	// write for any reason, so decay measured from it would silently become
	// zero the moment anything added a per-request counter or last_seen_at —
	// and risk scores would only ever climb.
	//
	// now() comes from the same query as the row, so decay is measured against
	// the database's clock rather than this process's. One clock, no skew.
	var (
		lockedTier, lockedRisk int
		lockedRiskAt, dbNow    time.Time
	)
	err = tx.QueryRow(ctx,
		`SELECT current_tier, risk_score, risk_updated_at, now()
		   FROM session_states WHERE session_id = $1 FOR UPDATE`,
		sess.ID).Scan(&lockedTier, &lockedRisk, &lockedRiskAt, &dbNow)
	if err != nil {
		// Includes pgx.ErrNoRows: Apply never conjures a session LoadOrCreate
		// did not make.
		return Session{}, fmt.Errorf("locking session %s: %w", sess.ID, err)
	}

	current, err := capability.ParseTier(lockedTier)
	if err != nil {
		return Session{}, fmt.Errorf("session %s: %w", sess.ID, err)
	}

	// The ratchet, re-applied against the locked value rather than d.From. A
	// decision computed when the session was at tier 0 cannot walk back a
	// demotion that landed in the meantime.
	final := capability.Stricter(current, d.To)

	// Decay and signal weight are applied separately, because they follow
	// different rules.
	//
	// Decay depends on how much time has passed, so it must be applied exactly
	// once no matter how many requests arrive. Signal weight depends on what
	// was detected, so every evaluation's contribution must be added.
	//
	// An earlier version used d.RiskAfter - d.RiskBefore as a single delta.
	// That is correct for signals and wrong for decay: ten concurrent requests
	// each carrying one half-life of decay subtracted ten half-lives, draining
	// an accumulated score of 50 to 0. Anyone could clear their own risk by
	// sending a handful of harmless requests at the same time.
	//
	// Decay is recomputed here from the LOCKED row's updated_at, so it reflects
	// time actually elapsed rather than whatever the caller read earlier.
	decayed := capability.Decay(lockedRisk, lockedRiskAt, dbNow, s.policy.HalfLife)
	risk := capability.ClampScore(decayed + d.SignalDelta)

	var (
		updated     Session
		updatedTier int
	)
	err = tx.QueryRow(ctx,
		`UPDATE session_states
		    SET current_tier = $2, risk_score = $3, risk_updated_at = now()
		  WHERE session_id = $1
		 RETURNING `+sessionColumns,
		sess.ID, int(final), risk,
	).Scan(&updated.ID, &updated.UserID, &updatedTier, &updated.RiskScore,
		&updated.CreatedAt, &updated.UpdatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("updating session %s: %w", sess.ID, err)
	}

	updated.Tier, err = capability.ParseTier(updatedTier)
	if err != nil {
		return Session{}, fmt.Errorf("session %s after update: %w", sess.ID, err)
	}
	updated.IdentityVerified = sess.IdentityVerified

	// The recorded downgrade is the transition that actually happened
	// (current -> final), not the one the decision proposed. A stale decision
	// claiming 0 -> 1 against a session already at 2 must not leave a row
	// describing a demotion that never occurred.
	for i, v := range vs {
		_, err := tx.Exec(ctx, `
			INSERT INTO guardrail_violations
				(session_id, request_id, direction, violation_source, llama_guard_code,
				 content_sha256, content_preview, raw_content,
				 applied_downgrade_from, applied_downgrade_to, metadata)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9, $10, $11)`,
			sess.ID, requestID, string(v.Direction), string(v.Source), v.LlamaGuardCode,
			v.ContentSHA256, v.ContentPreview, v.RawContent,
			int(current), int(final), v.Metadata)
		if err != nil {
			// Returning here rolls back the tier change too, which is the whole
			// reason for the transaction.
			return Session{}, fmt.Errorf("recording violation %d of %d: %w", i+1, len(vs), err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Session{}, fmt.Errorf("commit for session %s: %w", sess.ID, err)
	}
	return updated, nil
}

// ResetUser clears risk and restores full capability for a user's sessions
// inside the carry-forward window. See Store.ResetUser.
//
// risk_updated_at is reset alongside the score so the cleared state is current
// rather than something that immediately decays from a stale baseline.
func (s *PostgresStore) ResetUser(ctx context.Context, userID string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE session_states
		   SET current_tier = 0, risk_score = 0, risk_updated_at = now()
		 WHERE user_id = $1
		   AND updated_at > now() - $2::interval`,
		userID, carryForwardWindow)
	if err != nil {
		return 0, fmt.Errorf("resetting %q: %w", userID, err)
	}
	return tag.RowsAffected(), nil
}
