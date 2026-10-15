package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This file is the specification for WhoIs: every test names one behaviour.

const (
	testIssuer   = "https://id.example.com"
	testAudience = "openclaw-gateway"
	testSubject  = "user-alice"
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

// claims builds a valid set, which individual tests then spoil in one way each.
func claims() jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Subject:   testSubject,
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{testAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, c jwt.RegisteredClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return s
}

func request(token string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "http://gateway.local/v1/chat", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestWhoIs_ValidTokenIdentifiesTheUser(t *testing.T) {
	key := testRSAKey(t)
	a, err := NewRSA(&key.PublicKey, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("NewRSA: %v", err)
	}

	user, err := a.WhoIs(request(signRS256(t, key, claims())))
	if err != nil {
		t.Fatalf("WhoIs on a valid token: %v", err)
	}
	if user.ID != testSubject {
		t.Errorf("ID = %q, want %q", user.ID, testSubject)
	}
	// This is the whole reason for choosing JWTs over asserted identity.
	if !user.Verified {
		t.Error("Verified = false after checking a signature ourselves")
	}
	if user.ExpiresAt.IsZero() {
		t.Error("ExpiresAt not populated from the exp claim")
	}
}

func TestWhoIs_RejectsMissingCredentials(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	if _, err := a.WhoIs(request("")); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v, want ErrNoCredentials", err)
	}
}

func TestWhoIs_RejectsExpiredToken(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	c := claims()
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))

	if _, err := a.WhoIs(request(signRS256(t, key, c))); err == nil {
		t.Error("an expired token was accepted")
	}
}

func TestWhoIs_RejectsTokenWithNoExpiry(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	c := claims()
	c.ExpiresAt = nil // a token that never expires is a permanent credential

	if _, err := a.WhoIs(request(signRS256(t, key, c))); err == nil {
		t.Error("a token with no exp claim was accepted")
	}
}

func TestWhoIs_RejectsWrongIssuer(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	c := claims()
	c.Issuer = "https://attacker.example.com"

	if _, err := a.WhoIs(request(signRS256(t, key, c))); err == nil {
		t.Error("a token from an unexpected issuer was accepted")
	}
}

// A token minted for a different service must not work here, even if the same
// provider signed it.
func TestWhoIs_RejectsWrongAudience(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	c := claims()
	c.Audience = jwt.ClaimStrings{"some-other-service"}

	if _, err := a.WhoIs(request(signRS256(t, key, c))); err == nil {
		t.Error("a token for another audience was accepted")
	}
}

func TestWhoIs_RejectsSignatureFromAnotherKey(t *testing.T) {
	ours := testRSAKey(t)
	theirs := testRSAKey(t)
	a, _ := NewRSA(&ours.PublicKey, testIssuer, testAudience)

	if _, err := a.WhoIs(request(signRS256(t, theirs, claims()))); err == nil {
		t.Error("a token signed by an unrelated key was accepted")
	}
}

// Attack 1: the "none" algorithm. The token's own header claims it needs no
// signature. A verifier that trusts that header accepts anything.
//
// Note what actually rejects this: the key type. keyFunc hands back an
// *rsa.PublicKey, and the none method demands jwt.UnsafeAllowNoneSignatureType,
// so the two never match. Pinning would also catch it, but this test passes
// with pinning removed — see TestWhoIs_RejectsUnpinnedAlgorithmFamily for the
// one that guards the pinning itself.
func TestWhoIs_RejectsNoneAlgorithm(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims()).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("building unsigned token: %v", err)
	}

	if _, err := a.WhoIs(request(unsigned)); err == nil {
		t.Error("an unsigned alg=none token was accepted")
	}
}

// Attack 2: algorithm confusion. Against an RSA verifier, sign with HMAC using
// the *public* key as the shared secret. The public key is public, so anyone
// can do this.
//
// Same caveat as above: here it is the key type that saves us, since HMAC
// verification requires a []byte and keyFunc returns an *rsa.PublicKey. That is
// a genuine structural defence and worth keeping a test on, but it is not the
// pinning, and this test passes without it.
func TestWhoIs_RejectsAlgorithmConfusion(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	pubPEM, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims()).
		SignedString([]byte("this-stands-in-for-the-public-key"))
	if err != nil {
		t.Fatalf("building confused token: %v", err)
	}

	if _, err := a.WhoIs(request(pubPEM)); err == nil {
		t.Error("an HS256 token was accepted by an RS256 verifier")
	}
}

func TestWhoIs_RejectsEmptySubject(t *testing.T) {
	key := testRSAKey(t)
	a, _ := NewRSA(&key.PublicKey, testIssuer, testAudience)

	c := claims()
	c.Subject = "" // verifies fine, but identifies nobody

	if _, err := a.WhoIs(request(signRS256(t, key, c))); err == nil {
		t.Error("a token with no subject was accepted")
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name, header, want string
		wantErr            bool
	}{
		{name: "valid", header: "Bearer abc.def.ghi", want: "abc.def.ghi"},
		{name: "lowercase scheme", header: "bearer abc.def.ghi", want: "abc.def.ghi"},
		{name: "missing header", header: "", wantErr: true},
		{name: "wrong scheme", header: "Basic abc123", wantErr: true},
		{name: "no scheme", header: "abc.def.ghi", wantErr: true},
		{name: "empty token", header: "Bearer ", wantErr: true},
		{name: "embedded space", header: "Bearer abc def", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://x.local", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			got, err := BearerToken(r)
			if c.wantErr {
				if err == nil {
					t.Errorf("BearerToken(%q) = %q, want error", c.header, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("BearerToken(%q): %v", c.header, err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func signHS256(t *testing.T, secret []byte, c jwt.RegisteredClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return s
}

// NewHMAC shares newAuthenticator with NewRSA, so the issuer, audience and
// expiry checks are the same code. What is specific to it is the key: a short
// shared secret is brute-forceable, and a verifier that accepts one is worse
// than no verifier, because it looks like one.
func TestNewHMAC_RejectsShortSecret(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		if _, err := NewHMAC(make([]byte, n), testIssuer, testAudience); err == nil {
			t.Errorf("a %d-byte HMAC secret was accepted", n)
		}
	}
	if _, err := NewHMAC(make([]byte, 32), testIssuer, testAudience); err != nil {
		t.Errorf("a 32-byte secret was rejected: %v", err)
	}
}

func TestNewHMAC_RequiresIssuerAndAudience(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := NewHMAC(secret, "", testAudience); err == nil {
		t.Error("an empty issuer was accepted")
	}
	if _, err := NewHMAC(secret, testIssuer, ""); err == nil {
		t.Error("an empty audience was accepted")
	}
}

func TestNewRSA_RequiresKeyIssuerAndAudience(t *testing.T) {
	key := testRSAKey(t)
	if _, err := NewRSA(nil, testIssuer, testAudience); err == nil {
		t.Error("a nil public key was accepted")
	}
	if _, err := NewRSA(&key.PublicKey, "", testAudience); err == nil {
		t.Error("an empty issuer was accepted")
	}
	if _, err := NewRSA(&key.PublicKey, testIssuer, ""); err == nil {
		t.Error("an empty audience was accepted")
	}
}

func TestWhoIs_HMACIdentifiesTheUser(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	a, err := NewHMAC(secret, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("NewHMAC: %v", err)
	}

	user, err := a.WhoIs(request(signHS256(t, secret, claims())))
	if err != nil {
		t.Fatalf("WhoIs on a valid HS256 token: %v", err)
	}
	if user.ID != testSubject {
		t.Errorf("ID = %q, want %q", user.ID, testSubject)
	}
	if !user.Verified {
		t.Error("Verified = false after checking a signature ourselves")
	}

	// The mirror image of TestWhoIs_RejectsAlgorithmConfusion: an HMAC verifier
	// must not accept an RSA-signed token either.
	if _, err := a.WhoIs(request(signRS256(t, testRSAKey(t), claims()))); err == nil {
		t.Error("an RS256 token was accepted by an HMAC verifier")
	}
}

// The test that actually guards jwt.WithValidMethods.
//
// RSA-PSS (PS256) verifies with the very same *rsa.PublicKey that RS256 uses,
// so the key-type defence that catches the two attacks above does nothing here.
// Only the pinned algorithm list rejects it. Remove WithValidMethods from
// newParser and this test fails while every other test still passes.
//
// Why it matters: an attacker who can get a token minted under any algorithm
// your key material happens to support gets in, whatever your issuer intended.
func TestWhoIs_RejectsUnpinnedAlgorithmFamily(t *testing.T) {
	key := testRSAKey(t)
	a, err := NewRSA(&key.PublicKey, testIssuer, testAudience)
	if err != nil {
		t.Fatalf("NewRSA: %v", err)
	}

	pss, err := jwt.NewWithClaims(jwt.SigningMethodPS256, claims()).SignedString(key)
	if err != nil {
		t.Fatalf("signing PS256: %v", err)
	}

	if _, err := a.WhoIs(request(pss)); err == nil {
		t.Error("a PS256 token was accepted by a verifier pinned to RS256/384/512")
	}
}
