package samlsp

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lorodoes/saml"
)

var defaultJWTSigningMethod = jwt.SigningMethodRS256

// JWTTrackedRequestCodec encodes TrackedRequests as signed JWTs
type JWTTrackedRequestCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           *rsa.PrivateKey
}

var _ TrackedRequestCodec = JWTTrackedRequestCodec{}

// JWTTrackedRequestClaims represents the JWT claims for a tracked request.
type JWTTrackedRequestClaims struct {
	jwt.RegisteredClaims
	TrackedRequest
	SAMLAuthnRequest bool `json:"saml-authn-request"`
}

// Encode returns an encoded string representing the TrackedRequest.
func (s JWTTrackedRequestCodec) Encode(value TrackedRequest) (string, error) {
	now := saml.TimeNow()
	claims := JWTTrackedRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{s.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.MaxAge)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.Issuer,
			NotBefore: jwt.NewNumericDate(now), // TODO(ross): correct for clock skew
			Subject:   value.Index,
		},
		TrackedRequest:   value,
		SAMLAuthnRequest: true,
	}
	token := jwt.NewWithClaims(s.SigningMethod, claims)
	return token.SignedString(s.Key)
}

// Decode returns a Tracked request from an encoded string.
func (s JWTTrackedRequestCodec) Decode(signed string) (*TrackedRequest, error) {
	// parser := jwt.Parser{
	// 	ValidMethods: []string{s.SigningMethod.Alg()},
	// }
	claims := JWTTrackedRequestClaims{}

	//Parse the token with claims and custom keyfunc
	token, err := jwt.ParseWithClaims(signed, &claims, func(t *jwt.Token) (interface{}, error) {
		// Validate signing method and return the correct key
		if t.Method.Alg() != s.SigningMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.Key.Public(), nil
	})
	// token, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
	// 	return s.Key.Public(), nil
	// })

	if err != nil {
		return nil, err
	}

	// Check token validity
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Claims validation (Audience, Issuer, etc.) using the embedded RegisteredClaims
	_, err = claims.RegisteredClaims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("expected audience %q, got %q", s.Audience, claims.Audience)
	}
	_, err = claims.RegisteredClaims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("expected issuer %q, got %q", s.Issuer, claims.Issuer)
	}
	if claims.SAMLAuthnRequest != true {
		return nil, fmt.Errorf("expected saml-authn-request")
	}

	// Use the claims subject as the index
	claims.TrackedRequest.Index = claims.Subject
	return &claims.TrackedRequest, nil
}
