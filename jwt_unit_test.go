package jwt

import (
	"testing"
	"time"
)

type subTester struct {
	Str string `json:"str,omitempty"`
}

type authTester struct {
	Val string     `json:"val,omitempty"`
	Sub *subTester `json:"sub,omitempty"`
}

var (
	subTest  = &subTester{Str: "subtest"}
	authTest = &authTester{Val: "test", Sub: subTest}
)

type newArgs struct {
	iss string
	aud string
	key string
	exp time.Duration
}

type genArgs struct {
	uid  string
	auth *authTester
}

func TestUnitNew(t *testing.T) {
	a := &newArgs{exp: time.Second}
	a.iss, a.aud, a.key = "this", "this", "123"

	t.Run("new - invalid args", func(t *testing.T) {
		testUnitNewXxInvalidArgs(t, a)
	})

	t.Run("new - valid args", func(t *testing.T) {
		testUnitNewXxValidArgs(t, a)
	})
}

func testUnitNewXxInvalidArgs(t *testing.T, a *newArgs) {
	if _, err := New("", a.aud, a.key, a.exp); err == nil {
		t.Errorf("nil err for empty issuer")
	}

	if _, err := New(a.iss, "", a.key, a.exp); err == nil {
		t.Errorf("nil err for empty audience")
	}

	if _, err := New(a.iss, a.aud, "", a.exp); err == nil {
		t.Errorf("nil err for empty key")
	}

	if _, err := New(a.iss, a.aud, a.key, 0); err == nil {
		t.Errorf("nil err for 0 duration")
	}
}
func testUnitNewXxValidArgs(t *testing.T, a *newArgs) {
	j, err := New(a.iss, a.aud, a.key, a.exp)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if j == nil {
		t.Fatalf("got nil, want instance of jwt")
	}

	if j.issuer == "" {
		t.Errorf("missing issuer")
	}

	if j.audience == "" {
		t.Errorf("missing audience")
	}

	if len(j.key) == 0 {
		t.Errorf("missing key")
	}

	if j.expiry == 0 {
		t.Errorf("missing (or bad) expiry")
	}

}

func TestUnitNewClaims(t *testing.T) {
	iss, aud, key := "this", "this", "123"
	exp := time.Second * 32

	j, err := New(iss, aud, key, exp)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	a := &genArgs{uid: "9001", auth: authTest}

	t.Run("new claims - invalid args", func(t *testing.T) {
		testUnitNewClaimsXxInvalidArgs(t, j, a)
	})

	t.Run("new claims - valid args", func(t *testing.T) {
		testUnitNewClaimsXxValidArgs(t, j, a)
	})
}

func testUnitNewClaimsXxInvalidArgs(t *testing.T, j *JWT, a *genArgs) {
	if _, err := j.newClaims("", a.auth); err == nil {
		t.Errorf("nil err for empty uid")
	}
}

func testUnitNewClaimsXxValidArgs(t *testing.T, j *JWT, a *genArgs) {
	c, err := j.newClaims(a.uid, a.auth)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if c == nil {
		t.Fatalf("got nil, want instance of claims")
	}

	if c.Issuer == "" {
		t.Errorf("missing issuer")
	}

	if c.Audience == "" {
		t.Errorf("missing audience")
	}

	if c.Subject != a.uid {
		t.Errorf("subject: got %s, want %s", c.Subject, a.uid)
	}

	if c.IssuedAt == 0 {
		t.Errorf("missing (or bad) issuedat")
	}

	if c.IssuedAt > time.Now().Unix() {
		t.Errorf("issuedat set late")
	}

	if c.ExpiresAt == 0 {
		t.Errorf("missing (or bad) expiresat")
	}

	if c.ExpiresAt < time.Now().Unix()+30 {
		t.Errorf("expiresat set early")
	}
}

func TestUnitGenerate(t *testing.T) {
	iss, aud, key := "this", "this", "123"
	exp := time.Second * 32

	j, err := New(iss, aud, key, exp)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	a := &genArgs{uid: "9001", auth: authTest}

	t.Run("gen - invalid args", func(t *testing.T) {
		testUnitGenerateXxInvalidArgs(t, j, a)
	})

	t.Run("gen - valid args", func(t *testing.T) {
		testUnitGenerateXxValidArgs(t, j, a)
	})
}

func testUnitGenerateXxInvalidArgs(t *testing.T, j *JWT, a *genArgs) {
	if _, err := j.Generate("", a.auth); err == nil {
		t.Errorf("nil err for empty uid")
	}
}

func testUnitGenerateXxValidArgs(t *testing.T, j *JWT, a *genArgs) {
	tk, err := j.Generate(a.uid, a.auth)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if len(tk) < 16 {
		t.Errorf("token appears to not be created correctly")
	}
}

func TestUnitParseWithJWTClaims(t *testing.T) {
	iss, aud, key := "this", "this", "123"
	exp := time.Second

	j, err := New(iss, aud, key, exp)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	a := &genArgs{uid: "9001", auth: authTest}

	tk, err := j.Generate(a.uid, a.auth)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	t.Run("invalid parsetoken args", func(t *testing.T) {
		testUnitParseWithJWTClaimsXxInvalidArgs(t, j, tk)
	})

	t.Run("valid claims", func(t *testing.T) {
		testUnitParseWithJWTClaimsXxValidArgs(t, j, tk)
	})
}

func testUnitParseWithJWTClaimsXxInvalidArgs(t *testing.T, j *JWT, tk string) {
	a := &authTester{Sub: &subTester{}}

	if _, err := j.parseWithJWTClaims("", a); err == nil {
		t.Errorf("nil err for empty token")
	}

	if _, err := j.parseWithJWTClaims(tk+"x", a); err == nil {
		t.Errorf("nil err for corrupted token")
	}
}

func testUnitParseWithJWTClaimsXxValidArgs(t *testing.T, j *JWT, tk string) {
	a := &authTester{Sub: &subTester{}}
	c, err := j.parseWithJWTClaims(tk, a)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	at, ok := c.Auth.(*authTester)
	if !ok {
		t.Fatalf("cannot assert auth as *authTester")
	}

	if at.Val != authTest.Val {
		t.Errorf("authTest: got %s, want %s", at.Val, authTest.Val)
	}
}
