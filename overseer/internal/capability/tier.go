// Package capability implements the capability-tier security model: the set of
// execution privileges a session holds, and the rules by which it loses them.
//
// Everything here is pure — no I/O, no clock reads, no mutable package state
// reachable by a caller. That is deliberate. This is the layer where a bug is a
// security bug rather than an outage, so it must be exhaustively testable in
// isolation, and its decisions must be reproducible from their inputs alone.
//
// Where a choice exists between failing open and failing closed, this package
// fails closed.
package capability

import "fmt"

// Tier is a session's execution capability level. Higher is more restrictive.
type Tier int

const (
	// TierFull permits read/write/exec and every tool category.
	TierFull Tier = 0
	// TierConstrained permits read-only work: read-only SQL, search, static APIs.
	TierConstrained Tier = 1
	// TierQuarantined permits conversation only. The tools array is stripped.
	TierQuarantined Tier = 2
	// TierBlocked terminates the turn. The upstream model is never contacted.
	TierBlocked Tier = 3
)

const (
	MinTier = TierFull
	MaxTier = TierBlocked
)

// Valid reports whether t is one of the four defined tiers.
func (t Tier) Valid() bool { return t >= MinTier && t <= MaxTier }

func (t Tier) String() string {
	switch t {
	case TierFull:
		return "full"
	case TierConstrained:
		return "constrained"
	case TierQuarantined:
		return "quarantined"
	case TierBlocked:
		return "blocked"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// ParseTier converts a stored integer into a Tier.
//
// On invalid input it returns TierBlocked, not TierFull. A corrupt or
// out-of-range tier in the database must not be read as "unrestricted".
func ParseTier(v int) (Tier, error) {
	t := Tier(v)
	if !t.Valid() {
		return TierBlocked, fmt.Errorf("invalid tier %d: must be %d..%d", v, int(MinTier), int(MaxTier))
	}
	return t, nil
}

// stricter returns the more restrictive of two tiers. It is the ratchet
// primitive: capability may be taken away, never handed back.
func stricter(a, b Tier) Tier {
	if a > b {
		return a
	}
	return b
}
