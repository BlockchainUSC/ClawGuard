package auth

import (
	"errors"
	"net/http"
	"strings"
)

var (
	// ErrNoCredentials — the request carried nothing to check.
	ErrNoCredentials = errors.New("auth: no credentials presented")
	// ErrInvalidToken — something was presented and it did not hold up.
	ErrInvalidToken = errors.New("auth: token is not valid")
)

// Authenticator turns an HTTP request into a User.
//
// Implementations must fail closed: any doubt returns an error, never a User
// with a guessed ID. A wrong answer here silently attributes one person's
// behaviour to another's reputation.
type Authenticator interface {
	WhoIs(r *http.Request) (User, error)
}

// BearerToken pulls the credential out of an Authorization header.
//
// Every path that is not exactly right returns an error rather than an empty
// string that a caller might ignore.
//
// Which error: anything that is not a well-formed Bearer header — absent,
// another scheme, no scheme at all, an empty token — is ErrNoCredentials,
// because nothing was presented that this package is willing to call a bearer
// credential. ErrInvalidToken is reserved for something that was presented as
// one and then did not hold up.
func BearerToken(r *http.Request) (string, error) {
	if r == nil {
		return "", ErrNoCredentials
	}

	header := r.Header.Get("Authorization")
	if header == "" {
		return "", ErrNoCredentials
	}

	// Split once: the token itself may legitimately contain no spaces, but a
	// malformed header might contain several, and we want that rejected rather
	// than silently truncated.
	scheme, token, found := strings.Cut(header, " ")
	if !found {
		return "", ErrNoCredentials
	}

	// RFC 6750 says the scheme is case-insensitive.
	if !strings.EqualFold(scheme, "Bearer") {
		return "", ErrNoCredentials
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", ErrNoCredentials
	}
	if strings.ContainsAny(token, " \t") {
		return "", ErrInvalidToken
	}

	return token, nil
}
