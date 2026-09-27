package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// errUserProfileNotFound means the token is valid but Auth Service has no
// users row for this Keycloak account yet.
var errUserProfileNotFound = errors.New("user profile not found")

// authUser mirrors the fields booking-service needs from Auth Service's
// GET /api/users/me response.
type authUser struct {
	ID     uint   `json:"id"`
	Status string `json:"status"`
}

var authHTTPClient = &http.Client{Timeout: 5 * time.Second}

// fetchMyUser asks Auth Service for the caller's numeric users.id, forwarding
// the caller's own token. Keycloak tokens only carry the Keycloak UUID, but
// bookings.user_id stores users.id from auth_db.
func fetchMyUser(ctx context.Context, authorization string) (*authUser, error) {
	baseURL := strings.TrimRight(os.Getenv("AUTH_SERVICE_URL"), "/")
	if baseURL == "" {
		return nil, errors.New("AUTH_SERVICE_URL not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/users/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authorization)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth service unreachable: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errUserProfileNotFound
	default:
		return nil, fmt.Errorf("auth service returned status %d", resp.StatusCode)
	}

	var u authUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("error parsing auth service response: %w", err)
	}
	return &u, nil
}
