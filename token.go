package jwt

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"strings"
)

// Token is a struct that maps all parts of a JWT Token.
// Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
type Token struct {
	Raw       string
	Header    map[string]string
	Claims    Claims
	Signature string
	Valid     bool
}

// NewToken creates a new token with the specified id and expiration delta
func (jwt *JWT) NewToken(id string, plusExpire int64) Token {
	return Token{
		Header: map[string]string{
			"typ": "JWT",
			"alg": jwt.AlgName,
		},
		Claims: jwt.newClaims(id, plusExpire),
	}
}

// SignedString returns the complete, signed token
func (jwt *JWT) SignedString(t Token) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.signingString(); err != nil {
		return "", err
	}
	if sig, err = jwt.sign(sstr); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

func (jwt *JWT) sign(signingString string) (string, error) {
	hasher := hmac.New(jwt.HashFunc, jwt.Key)
	hasher.Write([]byte(signingString))
	return encodeSegment(hasher.Sum(nil)), nil
}

func (t *Token) signingString() (string, error) {
	var err error
	parts := make([]string, 2)

	var jsonValue []byte

	if jsonValue, err = json.Marshal(t.Header); err != nil {
		return "", err
	}
	parts[0] = encodeSegment(jsonValue)

	if jsonValue, err = json.Marshal(t.Claims); err != nil {
		return "", err
	}
	parts[1] = encodeSegment(jsonValue)

	return strings.Join(parts, "."), nil
}

// Compare two tokens
func (t *Token) Compare(token *Token) error {
	if t.Header["typ"] != token.Header["typ"] {
		return errors.New("Token Header[typ] differ")
	}

	if t.Header["alg"] != token.Header["alg"] {
		return errors.New("Token Header[alg] differ")
	}

	if err := t.Claims.Compare(token.Claims); err != nil {
		return err
	}

	return nil
}
