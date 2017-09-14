package jwt

import (
	"crypto/sha256"
	"hash"
	"time"
)

// JWT contains the main api
type JWT struct {
	Audience string
	Issuer   string
	Subject  string
	AlgName  string
	Key      []byte
	TimeFunc func() time.Time
	HashFunc func() hash.Hash
}

var algName = "HS256"
var criptoAlgorithm = sha256.New

// New allocates and returns a new JWT.
func New(audience string, issuer string, subject string, key string) *JWT {
	return &JWT{audience, issuer, subject, algName, []byte(key), time.Now, criptoAlgorithm}
}
