package jwt_test

import (
	"testing"
	"time"

	"github.com/levuer/jwt"
)

func TestJWTNewFunc(t *testing.T) {

	id := "tokenID"
	var plusExpire int64 = 30

	properties := map[string]string{
		"audience": "TestAudience",
		"issuer":   "TestIssuer",
		"subject":  "TestSubject",
		"key":      "TestKey",
	}

	j := jwt.New(properties["audience"], properties["issuer"], properties["subject"], properties["key"])

	if j.Audience != properties["audience"] || j.Issuer != properties["issuer"] || j.Subject != properties["subject"] || string(j.Key) != properties["key"] {
		t.Fatal("error comparing properties")
	}

	token := j.NewToken(id, plusExpire)
	signedTokenString, err := j.SignedString(token)

	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)

	parsedToken, err := j.ParseString(signedTokenString)

	if err != nil {
		t.Fatal(err)
	}

	if err = token.Compare(parsedToken); err != nil {
		t.Fatal(err)
	}
}
