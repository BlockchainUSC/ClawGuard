package auth

import (
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// JWTAuthenticator verifies signed tokens issued by your identity provider.
//
// The security of this type lives almost entirely in how the parser is
// configured — see newParser. The two classic ways to get JWT verification
// wrong:
//
//  1. Algorithm confusion. A token's own header names the algorithm used to
//     sign it. Trusting that header lets an attacker set it to "none" and send
//     an unsigned token, or — against an RSA verifier — set it to "HS256" and
//     sign with your *public* key as the HMAC secret, which is public.
//     WithValidMethods pins the acceptable algorithms so the header cannot
//     choose for us.
//
//  2. Forgetting that a valid signature only proves the token was issued, not
//     that it is still good, or that it was meant for us. Hence requiring exp,
//     and checking issuer and audience.
type JWTAuthenticator struct {
	parser  *jwt.Parser
	keyFunc jwt.Keyfunc
}

var _ Authenticator = (*JWTAuthenticator)(nil)

// NewRSA builds an authenticator for tokens signed with an RSA private key and
// verified with the matching public key. This is the usual shape when a
// separate identity provider issues the tokens: it holds the private key, you
// only ever need the public one.
func NewRSA(pub *rsa.PublicKey, issuer, audience string) (*JWTAuthenticator, error) {
	if pub == nil {
		return nil, fmt.Errorf("auth: nil RSA public key")
	}
	return newAuthenticator([]string{"RS256", "RS384", "RS512"}, issuer, audience, pub)
}

// NewHMAC builds an authenticator for tokens signed with a shared secret.
//
// Simpler to set up, but the verifier holds the same key that signs, so
// anything that can check a token can also mint one. Fine when one service both
// issues and verifies; wrong as soon as a second party needs to verify.
func NewHMAC(secret []byte, issuer, audience string) (*JWTAuthenticator, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("auth: HMAC secret must be at least 32 bytes, got %d", len(secret))
	}
	return newAuthenticator([]string{"HS256", "HS384", "HS512"}, issuer, audience, secret)
}

// newAuthenticator is the shared tail of both constructors. Only the key
// material and the pinned algorithm family differ between them; the issuer and
// audience requirement and the parser configuration are the same checks in both
// cases, and allowing two copies of them to drift is how one scheme ends up
// verifying less than the other.
//
// key is whatever the pinned methods verify against — an *rsa.PublicKey or an
// HMAC secret — and is handed back unchanged by keyFunc. A mismatch between the
// key's type and the token's algorithm is itself a rejection, which is what
// stops an RSA verifier from being talked into HMAC (see note 1 above).
func newAuthenticator(methods []string, issuer, audience string, key any) (*JWTAuthenticator, error) {
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("auth: issuer and audience are both required")
	}
	return &JWTAuthenticator{
		parser:  newParser(methods, issuer, audience),
		keyFunc: func(*jwt.Token) (any, error) { return key, nil },
	}, nil
}

func newParser(methods []string, issuer, audience string) *jwt.Parser {
	return jwt.NewParser(
		jwt.WithValidMethods(methods), // see note 1 above
		jwt.WithIssuer(issuer),        // token came from the provider we expect
		jwt.WithAudience(audience),    // token was minted for this gateway
		jwt.WithExpirationRequired(),  // a token with no exp never expires
	)
}

// WhoIs verifies the bearer token on the request and returns the user it
// identifies.
//
// Verified is set to true here, and only here: this is the one place in the
// system that checks a signature itself rather than taking someone's word.
func (a *JWTAuthenticator) WhoIs(r *http.Request) (User, error) {
	token, err := BearerToken(r)
	if err != nil {
		return User{}, err
	}
	claims := &jwt.RegisteredClaims{}

	if _, err := a.parser.ParseWithClaims(token, claims, a.keyFunc); err != nil {
		return User{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if claims.Subject == "" {
		return User{}, fmt.Errorf("%w: token has no subject", ErrInvalidToken)
	}
	// newParser passes WithExpirationRequired, so a token without exp has
	// already been rejected and this pointer cannot be nil. Checking anyway:
	// the guarantee lives in a different function, and whoever edits that
	// function next will not be looking at this line. A nil dereference here
	// panics the authenticator, which takes the gateway down.
	if claims.ExpiresAt == nil {
		return User{}, fmt.Errorf("%w: token has no expiry", ErrInvalidToken)
	}

	return User{
		ID:        claims.Subject,
		Verified:  true,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}
