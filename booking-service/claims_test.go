package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "http://localhost:8080/realms/unibook"

func newTestVerifier(t *testing.T) (*tokenVerifier, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyfunc := func(*jwt.Token) (interface{}, error) { return &key.PublicKey, nil }
	return newTokenVerifier(keyfunc, testIssuer), key
}

// makeTestToken builds a Keycloak-shaped access token signed with key.
func makeTestToken(t *testing.T, key *rsa.PrivateKey, extra jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":                testIssuer,
		"sub":                "a0e1c7d2-0000-4000-8000-000000000001",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"preferred_username": "phasakorn",
	}
	for k, v := range extra {
		claims[k] = v
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func realmRoles(roles ...string) jwt.MapClaims {
	return jwt.MapClaims{"realm_access": map[string]interface{}{"roles": roles}}
}

func TestVerifyReadsRealmRole(t *testing.T) {
	v, key := newTestVerifier(t)
	c, err := v.Verify(makeTestToken(t, key, realmRoles("offline_access", "USER")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Role != "USER" {
		t.Errorf("Role = %q, want USER", c.Role)
	}
	if c.Username != "phasakorn" {
		t.Errorf("Username = %q, want phasakorn", c.Username)
	}
}

func TestVerifyPicksMostPrivilegedRole(t *testing.T) {
	v, key := newTestVerifier(t)
	c, err := v.Verify(makeTestToken(t, key, realmRoles("USER", "ADMIN", "STAFF")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Role != "ADMIN" {
		t.Errorf("Role = %q, want ADMIN", c.Role)
	}
}

func TestVerifyMissingRole(t *testing.T) {
	v, key := newTestVerifier(t)
	if _, err := v.Verify(makeTestToken(t, key, realmRoles("offline_access"))); err == nil {
		t.Error("expected error for token without an app role")
	}
}

func TestVerifyIgnoresTopLevelRoleClaim(t *testing.T) {
	v, key := newTestVerifier(t)
	if _, err := v.Verify(makeTestToken(t, key, jwt.MapClaims{"role": "ADMIN"})); err == nil {
		t.Error("expected error: role must come from realm_access.roles")
	}
}

func TestVerifyRejectsWrongSignature(t *testing.T) {
	v, _ := newTestVerifier(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(makeTestToken(t, otherKey, realmRoles("ADMIN"))); err == nil {
		t.Error("expected error for token signed by another key")
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	v, key := newTestVerifier(t)
	extra := realmRoles("USER")
	extra["iss"] = "http://evil.example/realms/unibook"
	if _, err := v.Verify(makeTestToken(t, key, extra)); err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	v, key := newTestVerifier(t)
	extra := realmRoles("USER")
	extra["exp"] = time.Now().Add(-time.Minute).Unix()
	if _, err := v.Verify(makeTestToken(t, key, extra)); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestVerifyMalformed(t *testing.T) {
	v, _ := newTestVerifier(t)
	if _, err := v.Verify("not-a-jwt"); err == nil {
		t.Error("expected error for malformed token")
	}
}
