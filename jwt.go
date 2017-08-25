package jwt

import (
	"fmt"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWT ...
type JWT struct {
	issuer   string
	audience string
	key      []byte
	expiry   time.Duration
	signmeth jwt.SigningMethod
}

// New ...
func New(issuer, audience, key string, expiry time.Duration) (*JWT, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer must not be an empty string")
	}

	if audience == "" {
		return nil, fmt.Errorf("audience must not be an empty string")
	}

	if key == "" {
		return nil, fmt.Errorf("key must not be an empty string")
	}

	if expiry == 0 {
		return nil, fmt.Errorf("expiry must not be zero")
	}

	j := &JWT{
		issuer:   issuer,
		audience: audience,
		key:      []byte(key),
		expiry:   expiry,
		signmeth: jwt.SigningMethodHS256,
	}

	return j, nil
}

type claims struct {
	jwt.StandardClaims

	Auth interface{} `json:"auth,omitempty"`
}

func (j *JWT) newClaims(subject string, auth interface{}) (*claims, error) {
	if subject == "" {
		return nil, fmt.Errorf("subject must not be an empty string")
	}

	now := time.Now()

	c := &claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    j.issuer,
			Audience:  j.audience,
			Subject:   subject,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(j.expiry).Unix(),
		},
		Auth: auth,
	}

	return c, nil
}

// Generate ...
func (j *JWT) Generate(subject string, auth interface{}) (string, error) {
	c, err := j.newClaims(subject, auth)
	if err != nil {
		return "", err
	}

	t := jwt.NewWithClaims(j.signmeth, c)

	return t.SignedString(j.key)
}

// Parse ...
func (j *JWT) Parse(token string, auth interface{}) error {
	_, err := j.parseWithJWTClaims(token, auth)

	return err
}

func (j *JWT) parseWithJWTClaims(token string, auth interface{}) (*claims, error) {
	pt, err := jwt.ParseWithClaims(token, &claims{Auth: auth}, func(*jwt.Token) (interface{}, error) {
		return j.key, nil

	})

	if err != nil {
		return nil, fmt.Errorf("jwt: %s", err)
	}

	c, ok := pt.Claims.(*claims)
	if !ok || !pt.Valid {
		return nil, fmt.Errorf("can't parse token")
	}

	if c.Audience != j.issuer {
		return nil, fmt.Errorf("audience is not valid")
	}

	if c.Subject == "" {
		return nil, fmt.Errorf("missing subject")
	}

	if uid, err := strconv.ParseInt(c.Subject, 10, 64); err != nil || uid == 0 {
		return nil, fmt.Errorf("bad subject")
	}

	return c, nil
}

// Claims ...
type Claims struct {
	Issuer    string
	Audience  string
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Auth      interface{}
}

// ParseWithClaims ...
func (j *JWT) ParseWithClaims(token string, auth interface{}) (*Claims, error) {
	c, err := j.parseWithJWTClaims(token, auth)
	if err != nil {
		return nil, err
	}

	rc := &Claims{
		Issuer:    c.Issuer,
		Audience:  c.Audience,
		Subject:   c.Subject,
		IssuedAt:  time.Unix(c.IssuedAt, 0),
		ExpiresAt: time.Unix(c.ExpiresAt, 0),
		Auth:      auth,
	}

	return rc, nil
}
