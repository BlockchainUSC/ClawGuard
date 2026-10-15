package session_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"openclaw/oversight/overseer/internal/auth"
	"openclaw/oversight/overseer/internal/capability"
	"openclaw/oversight/overseer/internal/dbtest"
	"openclaw/oversight/overseer/internal/session"
)

// The specification for PostgresStore. Each test names one behaviour.

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func verifiedUser(id string) auth.User {
	return auth.User{ID: id, Verified: true}
}

func newSession(t *testing.T, s *session.PostgresStore, ctx context.Context, userID string) session.Session {
	t.Helper()
	sess, err := s.LoadOrCreate(ctx, session.NewID(), verifiedUser(userID))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return sess
}

// seedSession inserts a session row directly, with a chosen age.
//
// It cannot be done by creating a session and then UPDATEing updated_at: the
// BEFORE UPDATE trigger rewrites that column to clock_timestamp() on every
// update, so a backdated value never survives. INSERT does not fire that
// trigger, which is why this writes the row in one statement.
//
// Writing the row rather than going through Apply also isolates a LoadOrCreate
// bug from an Apply bug, which a test that uses Apply to set up its state
// cannot do.
func seedSession(t *testing.T, pool *pgxpool.Pool, ctx context.Context,
	userID string, tier, risk int, age time.Duration) session.Session {
	t.Helper()
	id := session.NewID()
	if _, err := pool.Exec(ctx, `
		INSERT INTO session_states (session_id, user_id, current_tier, risk_score, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now() - $5::interval, now() - $5::interval)`,
		id, userID, tier, risk, age.String()); err != nil {
		t.Fatalf("seeding session: %v", err)
	}
	return session.Session{ID: id, UserID: userID, Tier: capability.Tier(tier),
		RiskScore: risk, IdentityVerified: true}
}

func tierOf(t *testing.T, pool *pgxpool.Pool, ctx context.Context, id uuid.UUID) (int, int) {
	t.Helper()
	var tier, risk int
	if err := pool.QueryRow(ctx,
		`SELECT current_tier, risk_score FROM session_states WHERE session_id = $1`, id,
	).Scan(&tier, &risk); err != nil {
		t.Fatalf("reading session state: %v", err)
	}
	return tier, risk
}

func violationCount(t *testing.T, pool *pgxpool.Pool, ctx context.Context, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM guardrail_violations WHERE session_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("counting violations: %v", err)
	}
	return n
}

func hash64(c byte) string { return strings.Repeat(string(c), 64) }

// applyConcurrently runs one Apply per decision against the same session, all
// released together, and fails if any of them errors.
//
// Contention is the point: these tests exist because a lost update or a
// repeated decay step is invisible when the calls are serialised.
func applyConcurrently(t *testing.T, s *session.PostgresStore, ctx context.Context,
	sess session.Session, decisions []capability.Decision) {
	t.Helper()

	errs := make([]error, len(decisions))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, d := range decisions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release everyone together
			_, errs[i] = s.Apply(ctx, sess, d, nil)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Apply %d of %d: %v", i, len(decisions), err)
		}
	}
}

// ---------------------------------------------------------------------------
// LoadOrCreate.
// ---------------------------------------------------------------------------

func TestLoadOrCreate_NewUserStartsUnrestricted(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)

	got, err := s.LoadOrCreate(ctx, session.NewID(), verifiedUser("brand-new"))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if got.Tier != capability.TierFull {
		t.Errorf("tier = %s, want %s", got.Tier, capability.TierFull)
	}
	if got.RiskScore != 0 {
		t.Errorf("risk = %d, want 0", got.RiskScore)
	}
	if !got.IdentityVerified {
		t.Error("IdentityVerified did not carry over from auth.User")
	}
}

// Calling twice with the same id must return the same session, not create a
// second one. The gateway calls this on every request.
func TestLoadOrCreate_IsIdempotent(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	id := session.NewID()

	first, err := s.LoadOrCreate(ctx, id, verifiedUser("repeat"))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := s.LoadOrCreate(ctx, id, verifiedUser("repeat"))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.ID != second.ID || first.CreatedAt != second.CreatedAt {
		t.Errorf("a second call created a different session:\n %+v\n %+v", first, second)
	}
}

// The reason JWTs were worth the trouble. A user demoted in one session must
// not get a clean slate by starting another.
func TestLoadOrCreate_CarriesRiskForwardToANewSession(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	user := verifiedUser("repeat-offender")

	first, err := s.LoadOrCreate(ctx, session.NewID(), user)
	if err != nil {
		t.Fatalf("first session: %v", err)
	}

	demotion := capability.Decision{
		From: capability.TierFull, To: capability.TierQuarantined,
		SignalDelta: 70,
		Reasons:     []string{"test demotion"},
	}
	if _, err := s.Apply(ctx, first, demotion, nil); err != nil {
		t.Fatalf("applying demotion: %v", err)
	}

	// Same user, brand new session id — as if they had reconnected.
	fresh, err := s.LoadOrCreate(ctx, session.NewID(), user)
	if err != nil {
		t.Fatalf("second session: %v", err)
	}
	if fresh.Tier != capability.TierQuarantined {
		t.Errorf("reconnecting reset the tier to %s; the ratchet is bypassable", fresh.Tier)
	}
	if fresh.RiskScore == 0 {
		t.Error("reconnecting reset the risk score to zero")
	}
}

// A different person must not inherit someone else's punishment.
func TestLoadOrCreate_DoesNotLeakRiskBetweenUsers(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)

	guilty := newSession(t, s, ctx, "guilty")
	if _, err := s.Apply(ctx, guilty, capability.Decision{
		From: capability.TierFull, To: capability.TierBlocked, SignalDelta: 120,
	}, nil); err != nil {
		t.Fatalf("applying: %v", err)
	}

	innocent, err := s.LoadOrCreate(ctx, session.NewID(), verifiedUser("innocent"))
	if err != nil {
		t.Fatalf("innocent session: %v", err)
	}
	if innocent.Tier != capability.TierFull {
		t.Errorf("an unrelated user started at %s", innocent.Tier)
	}
}

// Carry-forward verified without going through Apply, by writing the prior
// session's state directly. This keeps the behaviour under test even while
// Apply is still a scaffold — and it isolates a LoadOrCreate bug from an
// Apply bug, which the two tests above cannot do.
func TestLoadOrCreate_CarryForwardIndependentOfApply(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	user := verifiedUser("prior-history")

	// A session this user was quarantined in, five minutes ago.
	seedSession(t, pool, ctx, user.ID, int(capability.TierQuarantined), 70, 5*time.Minute)

	fresh, err := s.LoadOrCreate(ctx, session.NewID(), user)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if fresh.Tier != capability.TierQuarantined {
		t.Errorf("new session tier = %s, want %s: reconnecting cleared the ratchet",
			fresh.Tier, capability.TierQuarantined)
	}
	if fresh.RiskScore != 70 {
		t.Errorf("risk = %d, want 70", fresh.RiskScore)
	}
}

// History older than the window must not follow the user forever.
func TestLoadOrCreate_CarryForwardExpiresWithTheWindow(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	user := verifiedUser("ancient-history")

	seedSession(t, pool, ctx, user.ID, int(capability.TierBlocked), 200, 30*24*time.Hour)

	fresh, err := s.LoadOrCreate(ctx, session.NewID(), user)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if fresh.Tier != capability.TierFull {
		t.Errorf("tier = %s, want %s: a 30-day-old demotion is outside the %s window",
			fresh.Tier, capability.TierFull, "24 hours")
	}
}

// Regression, B1. A session id is not authorisation.
//
// Before this check, a user blocked at tier 3 could present any other user's
// session id and be served at that session's tier — and every violation they
// then caused was filed against the other user.
func TestLoadOrCreate_RejectsAnotherUsersSession(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)

	victim := verifiedUser("victim")
	attacker := verifiedUser("attacker")

	victimSess, err := s.LoadOrCreate(ctx, session.NewID(), victim)
	if err != nil {
		t.Fatalf("victim session: %v", err)
	}

	// The attacker is blocked in their own session.
	attackerSess, err := s.LoadOrCreate(ctx, session.NewID(), attacker)
	if err != nil {
		t.Fatalf("attacker session: %v", err)
	}
	if _, err := s.Apply(ctx, attackerSess, capability.Decision{
		From: capability.TierFull, To: capability.TierBlocked, SignalDelta: 150,
	}, nil); err != nil {
		t.Fatalf("blocking the attacker: %v", err)
	}

	got, err := s.LoadOrCreate(ctx, victimSess.ID, attacker)
	if err == nil {
		t.Fatalf("attacker loaded the victim's session: tier=%s user=%q", got.Tier, got.UserID)
	}
	if !errors.Is(err, session.ErrSessionNotOwned) {
		t.Errorf("err = %v, want ErrSessionNotOwned", err)
	}
	if got.Tier != capability.TierFull || got.UserID != "" {
		t.Errorf("a rejected load still returned data: %+v", got)
	}

	// The victim's own session must be untouched by the attempt.
	still, err := s.LoadOrCreate(ctx, victimSess.ID, victim)
	if err != nil {
		t.Fatalf("victim reloading their own session: %v", err)
	}
	if still.UserID != "victim" {
		t.Errorf("victim session user_id = %q", still.UserID)
	}
}

// ---------------------------------------------------------------------------
// Apply.
// ---------------------------------------------------------------------------

// Decision and evidence are written together or not at all.
func TestApply_PersistsDecisionAndViolationsTogether(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "evidence")

	d := capability.Decision{
		From: capability.TierFull, To: capability.TierConstrained, SignalDelta: 35,
		Reasons: []string{"LLAMA_GUARD_3(S13) +35"},
	}
	vs := []session.Violation{{
		Direction:      session.Inbound,
		Source:         capability.SourceLlamaGuard,
		LlamaGuardCode: "S13",
		ContentSHA256:  hash64('0'),
		ContentPreview: "redacted",
	}}

	updated, err := s.Apply(ctx, sess, d, vs)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if updated.Tier != capability.TierConstrained {
		t.Errorf("tier = %s, want %s", updated.Tier, capability.TierConstrained)
	}
	if n := violationCount(t, pool, ctx, sess.ID); n != 1 {
		t.Errorf("violation rows = %d, want 1", n)
	}
}

// Demotions racing on one session must settle on the strictest tier, not on
// whichever transaction committed last.
//
// This test is PROBABILISTIC and must not be trusted as the row lock's guard.
// With FOR UPDATE removed it fails roughly three runs in five — real signal,
// but a coin flip, and a green run proves nothing. Its honest value is that
// concurrent Apply calls neither deadlock nor error under contention.
//
// TestApply_DoesNotLoseAnUpdateUnderRowContention is the deterministic guard:
// it constructs the losing interleaving instead of hoping for it, and fails
// every time the lock is removed.
func TestApply_ConcurrentDemotionsSettleOnTheStricterTier(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "racer")

	// One hard block against a crowd of milder demotions. Only the tier is
	// under test here, so every decision carries no signal weight.
	const mild = 15
	decisions := []capability.Decision{{From: capability.TierFull, To: capability.TierBlocked}}
	for i := 0; i < mild; i++ {
		decisions = append(decisions,
			capability.Decision{From: capability.TierFull, To: capability.TierConstrained})
	}
	applyConcurrently(t, s, ctx, sess, decisions)

	final, err := s.LoadOrCreate(ctx, sess.ID, verifiedUser("racer"))
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if final.Tier != capability.TierBlocked {
		t.Errorf("tier = %s after %d concurrent applies, want %s: a milder decision "+
			"overwrote a stricter one", final.Tier, len(decisions), capability.TierBlocked)
	}
}

// ---------------------------------------------------------------------------
// Apply: adversarial cases.
//
// The tests above mostly describe Apply working. These describe the ways it
// can quietly be wrong — stale reads, lost updates, partial writes, and races.
// ---------------------------------------------------------------------------

// If any violation fails to insert, the tier change must not survive either.
// A demotion recorded without its evidence is an unexplained punishment.
func TestApply_RollsBackEverythingWhenAViolationIsInvalid(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "rollback")

	vs := []session.Violation{
		{ // valid
			Direction: session.Inbound, Source: capability.SourceFastRegex,
			ContentSHA256: hash64('a'), ContentPreview: "ok",
		},
		{ // violates the violation_source CHECK constraint
			Direction: session.Inbound, Source: capability.Source("VIBES"),
			ContentSHA256: hash64('b'), ContentPreview: "bad",
		},
	}

	_, err := s.Apply(ctx, sess, capability.Decision{
		From: capability.TierFull, To: capability.TierQuarantined, SignalDelta: 70,
	}, vs)
	if err == nil {
		t.Fatal("Apply accepted a violation that violates a CHECK constraint")
	}

	tier, risk := tierOf(t, pool, ctx, sess.ID)
	if tier != int(capability.TierFull) || risk != 0 {
		t.Errorf("tier/risk = %d/%d after a failed Apply, want 0/0: the update was not rolled back", tier, risk)
	}
	if n := violationCount(t, pool, ctx, sess.ID); n != 0 {
		t.Errorf("%d violation rows survived a rolled-back transaction", n)
	}
}

// The caller's Session was read at some earlier point. If the session has been
// demoted since, a weaker decision must not walk it back.
func TestApply_StaleSessionCannotUndoANewerDemotion(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	stale := newSession(t, s, ctx, "stale-reader") // tier 0 at read time

	// Someone else quarantines it in the meantime.
	if _, err := s.Apply(ctx, stale, capability.Decision{
		From: capability.TierFull, To: capability.TierQuarantined, SignalDelta: 70,
	}, nil); err != nil {
		t.Fatalf("first demotion: %v", err)
	}

	// The holder of the stale struct now applies a milder decision.
	got, err := s.Apply(ctx, stale, capability.Decision{
		From: capability.TierFull, To: capability.TierConstrained, SignalDelta: 30,
	}, nil)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if got.Tier != capability.TierQuarantined {
		t.Errorf("tier = %s, want %s: a stale read undid a demotion", got.Tier, capability.TierQuarantined)
	}
}

func TestApply_IgnoresADecisionThatWouldPromote(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "promoter")

	demoted, err := s.Apply(ctx, sess, capability.Decision{
		From: capability.TierFull, To: capability.TierBlocked, SignalDelta: 120,
	}, nil)
	if err != nil {
		t.Fatalf("demoting: %v", err)
	}

	got, err := s.Apply(ctx, demoted, capability.Decision{
		From: capability.TierBlocked, To: capability.TierFull, SignalDelta: 0,
	}, nil)
	if err != nil {
		t.Fatalf("promotion attempt: %v", err)
	}
	if got.Tier != capability.TierBlocked {
		t.Errorf("tier = %s, want %s: capability was handed back", got.Tier, capability.TierBlocked)
	}
}

// The row records what actually happened, not what was proposed. A stale
// decision claiming From=0 against a session already at 2 must not be logged
// as a 0 -> 1 downgrade that never occurred.
func TestApply_RecordsTheTransitionThatActuallyHappened(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "bookkeeping")

	if _, err := s.Apply(ctx, sess, capability.Decision{
		From: capability.TierFull, To: capability.TierQuarantined, SignalDelta: 70,
	}, nil); err != nil {
		t.Fatalf("first demotion: %v", err)
	}

	_, err := s.Apply(ctx, sess, capability.Decision{
		From: capability.TierFull, To: capability.TierConstrained, SignalDelta: 30,
	}, []session.Violation{{
		Direction: session.Outbound, Source: capability.SourceToolValidator,
		ContentSHA256: hash64('c'), ContentPreview: "p",
	}})
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	var from, to int
	if err := pool.QueryRow(ctx, `
		SELECT applied_downgrade_from, applied_downgrade_to
		  FROM guardrail_violations WHERE session_id = $1
		 ORDER BY id DESC LIMIT 1`, sess.ID).Scan(&from, &to); err != nil {
		t.Fatalf("reading violation: %v", err)
	}
	if from != int(capability.TierQuarantined) || to != int(capability.TierQuarantined) {
		t.Errorf("recorded %d -> %d, want 2 -> 2 (the real, no-op transition)", from, to)
	}
}

// Apply must not conjure a session that LoadOrCreate never made.
func TestApply_FailsOnUnknownSession(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)

	ghost := session.Session{ID: session.NewID(), UserID: "ghost", Tier: capability.TierFull}
	if _, err := s.Apply(ctx, ghost, capability.Decision{
		From: capability.TierFull, To: capability.TierConstrained, SignalDelta: 30,
	}, nil); err == nil {
		t.Error("Apply succeeded against a session that does not exist")
	}
	if n := violationCount(t, pool, ctx, ghost.ID); n != 0 {
		t.Errorf("%d violations written for a nonexistent session", n)
	}
}

// Decay-only evaluations produce a decision with no evidence. That is valid.
func TestApply_AcceptsADecisionWithNoViolations(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "quiet")

	if _, err := s.Apply(ctx, sess, capability.Decision{
		From: capability.TierFull, To: capability.TierFull, SignalDelta: 5,
	}, nil); err != nil {
		t.Fatalf("Apply with no violations: %v", err)
	}
	if _, risk := tierOf(t, pool, ctx, sess.ID); risk != 5 {
		t.Errorf("risk = %d, want 5", risk)
	}
}

// Two evaluations that each observed risk 0 and each added 10 must total 20.
// Writing RiskAfter as an absolute would lose one of them.
func TestApply_ConcurrentRiskIncrementsAreNotLost(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "accumulator")

	increment := capability.Decision{
		From: capability.TierFull, To: capability.TierFull, SignalDelta: 10,
	}
	applyConcurrently(t, s, ctx, sess, []capability.Decision{increment, increment})

	if _, risk := tierOf(t, pool, ctx, sess.ID); risk != 20 {
		t.Errorf("risk = %d, want 20: a concurrent increment was lost", risk)
	}
}

// risk_score has a CHECK (risk_score >= 0), so decay must never drive it below
// zero no matter how long a session has been idle.
func TestApply_RiskNeverGoesNegative(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)

	// A small score, left to rot for a year.
	sess := seedSession(t, pool, ctx, "decayer", 0, 3, 365*24*time.Hour)

	got, err := s.Apply(ctx, sess, capability.Decision{
		From: capability.TierFull, To: capability.TierFull, SignalDelta: 0,
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got.RiskScore != 0 {
		t.Errorf("risk = %d, want 0 after a year of decay", got.RiskScore)
	}
}

// Deterministically forces the lost-update interleaving, rather than hoping
// goroutines collide.
//
// The test itself holds a row lock, lets an Apply start underneath it, then
// demotes the row and releases. Without FOR UPDATE, Apply's plain SELECT reads
// the pre-demotion tier immediately (MVCC does not block it), computes its
// result from that stale value, and only blocks at the UPDATE — so it writes a
// milder tier over the stricter one. With FOR UPDATE, its read waits and then
// sees the committed demotion.
func TestApply_DoesNotLoseAnUpdateUnderRowContention(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	sess := newSession(t, s, ctx, "contended")

	// Hold the row.
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin blocker: %v", err)
	}
	var held int
	if err := blocker.QueryRow(ctx,
		`SELECT current_tier FROM session_states WHERE session_id = $1 FOR UPDATE`,
		sess.ID).Scan(&held); err != nil {
		t.Fatalf("taking the lock: %v", err)
	}

	// A mild decision, computed against the tier as it stands now (0).
	done := make(chan error, 1)
	go func() {
		_, err := s.Apply(ctx, sess, capability.Decision{
			From: capability.TierFull, To: capability.TierConstrained,
			SignalDelta: 30,
		}, nil)
		done <- err
	}()

	// Give the goroutine time to reach its read. A correct Apply blocks here;
	// an incorrect one has already read the stale tier and is waiting to write.
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("Apply completed while the row was locked: %v", err)
	default:
	}

	// Demote hard, then release.
	if _, err := blocker.Exec(ctx,
		`UPDATE session_states SET current_tier = 3, risk_score = 120 WHERE session_id = $1`,
		sess.ID); err != nil {
		t.Fatalf("demoting under the lock: %v", err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("commit blocker: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("Apply: %v", err)
	}

	tier, _ := tierOf(t, pool, ctx, sess.ID)
	if tier != int(capability.TierBlocked) {
		t.Errorf("tier = %d, want %d: Apply overwrote a demotion it never saw",
			tier, int(capability.TierBlocked))
	}
}

// Regression, B2. Concurrent requests must not multiply decay.
//
// Before the fix, each concurrent Apply subtracted a full decay step from the
// same locked value, so N parallel harmless requests erased N half-lives.
// A score of 50 drained to 0 with ten of them.
func TestApply_ConcurrentDecayIsAppliedOnlyOnce(t *testing.T) {
	pool, ctx := dbtest.Pool(t)
	s := session.NewPostgresStore(pool)
	// 50 points of risk, one half-life ago. DefaultPolicy's half-life is 30m.
	sess := seedSession(t, pool, ctx, "drainer", 0, 50, 30*time.Minute)

	const n = 10
	decisions := make([]capability.Decision, n)
	for i := range decisions {
		decisions[i] = capability.Decision{
			From: capability.TierFull, To: capability.TierFull, SignalDelta: 0,
		}
	}
	applyConcurrently(t, s, ctx, sess, decisions)

	_, risk := tierOf(t, pool, ctx, sess.ID)
	if risk != 25 {
		t.Errorf("risk = %d after %d concurrent decay-only applies, want 25 "+
			"(one half-life of 50). Decay was applied more than once.", risk, n)
	}
}
