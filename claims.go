package jwt

import (
	"crypto/subtle"
	"errors"
)

// Claims is a structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
type Claims struct {
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	ID        string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	Issuer    string `json:"iss"`
	NotBefore int64  `json:"nbf"`
	Subject   string `json:"sub"`
}

func (jwt *JWT) newClaims(id string, plusExpire int64) Claims {
	expire := jwt.TimeFunc().Unix() + plusExpire
	return Claims{
		Audience:  jwt.Audience,
		ExpiresAt: expire,
		ID:        id,
		IssuedAt:  jwt.TimeFunc().Unix(),
		Issuer:    jwt.Issuer,
		NotBefore: jwt.TimeFunc().Unix(),
		Subject:   jwt.Subject,
	}
}

func (jwt *JWT) validateClaims(c Claims) error {
	now := jwt.TimeFunc().Unix()
	if subtle.ConstantTimeCompare([]byte(c.Audience), []byte(jwt.Audience)) == 0 {
		return ErrInvalidAudience
	}
	if now >= c.ExpiresAt {
		return ErrTokenExpired
	}
	if now <= c.IssuedAt {
		return ErrTokenUsedBeforeIssued
	}
	if subtle.ConstantTimeCompare([]byte(c.Issuer), []byte(jwt.Issuer)) == 0 {
		return ErrInvalidIssuer
	}
	if now <= c.NotBefore {
		return ErrTokenNotValidYet
	}
	if subtle.ConstantTimeCompare([]byte(c.Subject), []byte(jwt.Subject)) == 0 {
		return ErrInvalidSubject
	}
	return nil
}

// Compare two claims
func (c *Claims) Compare(claims Claims) error {
	if c.Audience != claims.Audience {
		return errors.New("Audience differ")
	}

	if c.ExpiresAt != claims.ExpiresAt {
		return errors.New("ExpiresAt differ")
	}

	if c.ID != claims.ID {
		return errors.New("ID differ")
	}

	if c.IssuedAt != claims.IssuedAt {
		return errors.New("IssuedAt differ")
	}

	if c.Issuer != claims.Issuer {
		return errors.New("Issuer differ")
	}

	if c.NotBefore != claims.NotBefore {
		return errors.New("NotBefore differ")
	}

	if c.Subject != claims.Subject {
		return errors.New("Subject differ")
	}

	return nil
}
