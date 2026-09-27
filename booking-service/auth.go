package main

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// authRequired verifies the Keycloak Bearer token Kong forwards through
// unchanged (see claims.go), looks up the caller's numeric users.id in Auth
// Service (see authuser.go), and stores user_id/username/role on the Gin
// context for handlers and requireRole() to use.
func authRequired(verifier *tokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := verifier.Verify(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: " + err.Error()})
			return
		}

		user, err := fetchMyUser(c.Request.Context(), authHeader)
		switch {
		case errors.Is(err, errUserProfileNotFound):
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "User profile not found in Auth Service"})
			return
		case err != nil:
			log.Printf("authRequired: %v", err)
			c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "Failed to look up user"})
			return
		case user.Status == "DEACTIVATED":
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "User account is deactivated"})
			return
		}
		claims.UserID = user.ID

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

// requireRole aborts with 403 unless authRequired() already put one of the
// given roles on the context. Every service in the team should implement
// this the same way (same claim names, same middleware shape) so a booking
// developed here behaves identically once Auth Service issues real tokens.
func requireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		roleStr, _ := role.(string)
		if !allowed[roleStr] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions for this action"})
			return
		}
		c.Next()
	}
}
