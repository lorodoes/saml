package samlsp

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/uuid"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lorodoes/saml"
)

const (
	defaultSessionMaxAge  = time.Hour
	claimNameSessionIndex = "SessionIndex"
)

// JWTSessionCodec implements SessionCoded to encode and decode Sessions from
// the corresponding JWT.
type JWTSessionCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           *rsa.PrivateKey
}

var _ SessionCodec = JWTSessionCodec{}

// New creates a Session from the SAML assertion.
//
// The returned Session is a JWTSessionClaims.
func (c JWTSessionCodec) New(assertion *saml.Assertion) (Session, error) {
	now := saml.TimeNow()
	claims := JWTSessionClaims{}
	claims.SAMLSession = true
	claims.Audience = jwt.ClaimStrings{c.Audience}
	claims.Issuer = c.Issuer
	claims.IssuedAt = jwt.NewNumericDate(now)
	expiresat := now.Add(c.MaxAge)
	claims.ExpiresAt = jwt.NewNumericDate(expiresat)
	claims.NotBefore = jwt.NewNumericDate(now)

	if sub := assertion.Subject; sub != nil {
		if nameID := sub.NameID; nameID != nil {
			claims.Subject = nameID.Value
		}
	}

	Attributes := map[string][]string{}
	claims.Attributes = map[string][]string{}

	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			claimName := attr.FriendlyName
			if claimName == "" {
				claimName = attr.Name
			}
			for _, value := range attr.Values {
				Attributes[claimName] = append(Attributes[claimName], value.Value)
			}
		}
	}

	// add SessionIndex to claims Attributes
	for _, authnStatement := range assertion.AuthnStatements {
		claims.Attributes[claimNameSessionIndex] = append(claims.Attributes[claimNameSessionIndex],
			authnStatement.SessionIndex)
	}

	log.Debugf("Attributes: %#v", Attributes)

	//strExpiresAt := fmt.Sprintf("%s", expiresat)
	strExpiresAt := expiresat.String()

	Attributes["ExpiresAtSAML"] = append(Attributes["ExpiresAtSAML"], strExpiresAt)

	log.Debugf("Turning claims in to json")
	mapAsBytes, _ := json.Marshal(Attributes)
	mapstring := string(mapAsBytes)
	log.Debugf("attribute string: %s", mapstring)
	log.Debugf("Create UUID")
	id := uuid.New()
	log.Debugf("Stringify UUID")
	stringid := id.String()
	log.Debugf("String into memory map")
	saml.UserAttributes[stringid] = mapstring
	log.Debugf("append string id in to attributes")
	claims.Attributes["id"] = append(claims.Attributes["id"], stringid)

	log.Debugf("Returning Claims")
	return claims, nil
}

// Encode returns a serialized version of the Session.
//
// The provided session must be a JWTSessionClaims, otherwise this
// function will panic.
func (c JWTSessionCodec) Encode(s Session) (string, error) {
	claims := s.(JWTSessionClaims) // this will panic if you pass the wrong kind of session

	token := jwt.NewWithClaims(c.SigningMethod, claims)
	signedString, err := token.SignedString(c.Key)
	if err != nil {
		return "", err
	}

	return signedString, nil
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c JWTSessionCodec) Decode(signed string) (Session, error) {
	log.Debugf("Starting Debug")

	claims := JWTSessionClaims{}
	// Parse the token with claims and custom keyfunc
	token, err := jwt.ParseWithClaims(signed, &claims, func(t *jwt.Token) (interface{}, error) {
		// Validate signing method and return the correct key
		if t.Method.Alg() != c.SigningMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return c.Key.Public(), nil
	})

	// Check for errors during parsing
	if err != nil {
		return nil, err
	}

	// Check token validity
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Claims validation (Audience, Issuer) using the embedded RegisteredClaims
	_, err = claims.RegisteredClaims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("expected audience %q, got %q", c.Audience, claims.Audience)
	}
	_, err = claims.RegisteredClaims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("expected issuer %q, got %q", c.Issuer, claims.Issuer)
	}
	if !claims.SAMLSession {
		return nil, errors.New("expected saml-session")
	}
	return claims, nil
}

// JWTSessionClaims represents the JWT claims in the encoded session
type JWTSessionClaims struct {
	jwt.RegisteredClaims
	Attributes  Attributes `json:"attr"`
	SAMLSession bool       `json:"saml-session"`
}

var _ Session = JWTSessionClaims{}

// GetAttributes implements SessionWithAttributes. It returns the SAMl attributes.
func (c JWTSessionClaims) GetAttributes() Attributes {
	return c.Attributes
}

// Attributes is a map of attributes provided in the SAML assertion
type Attributes map[string][]string

// Get returns the first attribute named `key` or an empty string if
// no such attributes is present.
func (a Attributes) Get(key string) string {
	if a == nil {
		return ""
	}
	v := a[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
