// Package auth answers one question: who is this request from?
//
// Nothing else in the system reads an Authorization header. Callers depend on
// the Authenticator interface, so swapping the scheme — API keys today, JWTs
// tomorrow, mTLS later — touches this package and nothing else.
package auth

import "time"

// User is the answer. ID is what reputation accrues to; it is the user_id
// column in session_states.
type User struct {
	ID string

	// Verified records how the ID was established.
	//
	// true  — the gateway checked a signature itself. Nobody could have forged
	//         this without the signing key.
	// false — some trusted client asserted it. As trustworthy as that client.
	//
	// This travels into the audit log on purpose. A demotion carried forward
	// from an unverified identity is weaker evidence than one from a verified
	// identity, and six months from now you will want to know which you had.
	Verified bool

	// ExpiresAt is when the credential stops being valid, zero if it never does.
	ExpiresAt time.Time
}
