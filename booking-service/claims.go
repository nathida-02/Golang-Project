package main

import (
	"errors"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the subset of token data this service relies on.
type Claims struct {
	UserID   uint
	Username string
	Role     string
}

// keycloakClaims mirrors the fields of a Keycloak access token that we use.
// Roles live in realm_access.roles (same as auth-service/notification-service).
// The subject (sub) is the Keycloak user UUID, not the numeric users.id —
// that is resolved separately through Auth Service (see authuser.go).
type keycloakClaims struct {
	jwt.RegisteredClaims
	PreferredUsername string `json:"preferred_username"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// rolePriority lists the app roles from most to least privileged. A Keycloak
// token also carries default roles (offline_access, uma_authorization, ...)
// which are ignored.
var rolePriority = []string{"ADMIN", "STAFF", "USER"}

// primaryRole picks the most privileged app role, or "" if there is none.
func primaryRole(roles []string) string {
	for _, r := range rolePriority {
		if slices.Contains(roles, r) {
			return r
		}
	}
	return ""
}

// tokenVerifier checks that a bearer token was really issued by Keycloak
// (valid RS256 signature, not expired, matching issuer).
type tokenVerifier struct {
	parser  *jwt.Parser
	keyfunc jwt.Keyfunc
}

func newTokenVerifier(keyfunc jwt.Keyfunc, issuer string) *tokenVerifier {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	return &tokenVerifier{parser: jwt.NewParser(opts...), keyfunc: keyfunc}
}

// Verify validates the token and returns its claims. UserID is left at 0;
// the caller fills it in from Auth Service.
func (v *tokenVerifier) Verify(token string) (*Claims, error) {
	var kc keycloakClaims
	if _, err := v.parser.ParseWithClaims(token, &kc, v.keyfunc); err != nil {
		return nil, err
	}

	role := primaryRole(kc.RealmAccess.Roles)
	if role == "" {
		return nil, errors.New("token missing role claim")
	}

	username := kc.PreferredUsername
	if username == "" {
		username = kc.Subject
	}
	return &Claims{Username: username, Role: role}, nil
}
