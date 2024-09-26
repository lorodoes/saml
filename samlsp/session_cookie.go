package samlsp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	b64 "encoding/base64"

	log "github.com/sirupsen/logrus"

	"github.com/andybalholm/brotli"
	"github.com/lorodoes/saml"
)

const defaultSessionCookieName = "token"

var _ SessionProvider = CookieSessionProvider{}

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Codec    SessionCodec
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	log.Debugf("Create Cookie Session")
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	log.Debugf("Creating the assertion")
	session, err := c.Codec.New(assertion)
	if err != nil {
		log.Debugf("Error Creating the assertion")
		return err
	}

	log.Debugf("Encoding the Session")
	value, err := c.Codec.Encode(session)
	if err != nil {
		log.Debugf("Error Encoding the Session")
		return err
	}

	var uEnc string
	if c.Domain != "15661444.ngrok.io" {
		log.Debug("Compressing")
		b := compressBrotli([]byte(value))
		uEnc = b64.URLEncoding.EncodeToString(b)
	} else {
		log.Debug("Skipped compression")
		uEnc = value
	}

	cookie := &http.Cookie{
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    uEnc,
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
		SameSite: c.SameSite,
		Path:     "/",
	}

	log.Debugf("Setting the Cookie")
	http.SetCookie(w, cookie)
	log.Debugf("Cookie Set")
	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c CookieSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	log.Debugf("Delete Session")
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	cookie, err := r.Cookie(c.Name)

	if err == http.ErrNoCookie {
		return nil
	}
	if err != nil {
		return err
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	cookie.Path = "/"
	cookie.Domain = c.Domain
	http.SetCookie(w, cookie)
	return nil
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (c CookieSessionProvider) GetSession(r *http.Request) (Session, error) {
	log.Debugf("SAML: Get Session")

	cookie, err := r.Cookie(c.Name)
	if err == http.ErrNoCookie {
		log.Debugf("Get Session: Error No Session")
		log.Errorf("Get Session: Error No Session: %s", err)
		return nil, ErrNoSession
	} else if err != nil {
		log.Debugf("Get Session: Error: %s", err)
		return nil, err
	}

	var d string
	// Check if the cookie is Base64URL encoded and decompress it if it is
	// If not, just use the cookie value as the session data
	log.Debugf("Checking if the cookie is Base64URL encoded")
	if isBase64URLEncoded(cookie.Value) {
		log.Debug("We have a Base64URL encoded string")
		log.Debug("Decoding the Base64URL encoded string")
		// Decode the Base64URL encoded string
		// Check if the decoded string is compressed using Brotli
		// If it is, decompress it
		// If not, just use the decoded string as the session data
		log.Debug("Decoding the Base64URL encoded string")
		uDec, _ := b64.URLEncoding.DecodeString(cookie.Value)
		if isByteSlice(uDec) {
			d, err := decompressBrotli(uDec)
			if err != nil {
				log.Debugf("Get Session: Error Decompress")
				log.Errorf("Get Session: Error Decompress: %s", err)
				return nil, err
			}
			if isString(d) {
				log.Debug("We have a string")
			} else {
				log.Debug("We do not have a string")
			}
		}
	} else {
		d = cookie.Value
		if isString(d) {
			log.Debug("We have a string")
		} else {
			log.Debug("We do not have a string")
		}
	}

	log.Debugf("Decoding the Session")
	session, err := c.Codec.Decode(d)
	if err != nil {
		log.Errorf("Cookie Session Decode Error:%s", err)
		log.Debugf("Get Session decode: Error No Session")
		return nil, ErrNoSession
	}
	log.Debugf("Returning the session")
	return session, nil
}

func compressBrotli(data []byte) []byte {
	var b bytes.Buffer
	w := brotli.NewWriterLevel(&b, brotli.BestCompression)
	_, err := w.Write(data)
	if err != nil {
		log.Errorf("Compression Failed: %s", err)
		return nil
	}
	w.Close()
	return b.Bytes()
}

func decompressBrotli(compressedData []byte) (string, error) {
	reader := brotli.NewReader(bytes.NewReader(compressedData))
	var decompressedData strings.Builder
	_, err := io.Copy(&decompressedData, reader)
	if err != nil {
		log.Errorf("Decompression Failed: %s", err)
		return "", fmt.Errorf("decompression failed: %w", err)
	}
	return decompressedData.String(), nil
}

func isBase64URLEncoded(s string) bool {
	// Try to decode the string
	_, err := b64.URLEncoding.DecodeString(s)
	return err != nil
}

func isByteSlice(v interface{}) bool {
	_, ok := v.([]byte)
	return ok
}

func isString(v interface{}) bool {
	_, ok := v.(string)
	return ok
}
