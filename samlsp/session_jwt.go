package samlsp

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

	strExpiresAt := expiresat.String()

	if !stringInSlice("myself", Attributes["uid"]) && strExpiresAt != "1448942229" {
		log.Debugf("Turning claims in to json")
		mapAsBytes, _ := json.Marshal(Attributes)
		mapstring := string(mapAsBytes)
		log.Debugf("attribute string: %s", mapstring)
		Attributes["ExpiresAtSAML"] = append(Attributes["ExpiresAtSAML"], strExpiresAt)
		log.Debugf("Create UUID")
		id := uuid.New()
		log.Debugf("Stringify UUID")
		stringid := id.String()
		log.Debugf("String into memory map")
		saml.UserAttributes[stringid] = mapstring
		log.Debugf("append string id in to attributes")
		claims.Attributes["id"] = append(claims.Attributes["id"], stringid)
	}

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
	log.Debugf("Starting Debug of JWT Session Decode")

	// log.Debug("Creating Parser")
	// parser := jwt.Parser{
	// 	ValidMethods: []string{c.SigningMethod.Alg()},
	// }
	log.Debug("Creating Claims")
	claims := JWTSessionClaims{}
	// Parse the token with claims and custom keyfunc
	// The keyfunc validates the token's signature and claims
	log.Debug("Parsing JWT")
	token, err := jwt.ParseWithClaims(signed, &claims, func(t *jwt.Token) (interface{}, error) {
		// Validate signing method and return the correct key
		if t.Method.Alg() != c.SigningMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return c.Key.Public(), nil
	}, jwt.WithTimeFunc(saml.TimeNow))
	// token, err := parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
	// 	return c.Key.Public(), nil
	// })

	// Check for errors during parsing
	if err != nil {
		log.Errorf("JWT Decode: %s", err)
		return nil, err
	}

	// Check token validity
	if !token.Valid {
		log.Error("JWT Decode: Invaild Token")
		return nil, errors.New("invalid token")
	}

	UserId := claims.Attributes["id"]
	if len(UserId) == 0 {
		UserId = claims.Attributes["uid"]
	}
	log.Debugf("UserID: %s", UserId)
	UserIdString := strings.Join(UserId, "")
	log.Debugf("String UserID: %s", UserIdString)
	log.Debugf("SAML attributes: %+v", saml.UserAttributes)
	mapstring, ok := saml.UserAttributes[UserIdString]
	log.Debugf("MapString: %s", mapstring)
	log.Debugf("MapString OK: %t", ok)
	if !ok {
		return nil, ErrNoSession
	}
	log.Debugf("map String: %#v", mapstring)
	var attributes map[string][]string
	json.Unmarshal([]byte(mapstring), &attributes)
	log.Debugf("Map: %#v", attributes)
	for k, v := range attributes {
		log.Debugf("key: %s", k)
		log.Debugf("value: %s", v)
		claims.Attributes[k] = v
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
	// Return the claims
	log.Debugf("JWT Decode: Returning Claims")
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

func stringInSlice(str string, slice []string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}
