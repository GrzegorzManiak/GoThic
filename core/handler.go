package core

import (
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/helpers"
	"github.com/grzegorzmaniak/gothic/rbac"
)

type Handler[BaseRoute helpers.BaseRouteComponents] struct {
	BaseRoute      BaseRoute
	Context        *gin.Context
	Claims         *SessionClaims
	SessionGroup   string
	SessionHeader  *SessionHeader
	CsrfToken      *CompleteCsrfToken
	HasSession     bool
	SessionManager SessionManager
}

type APIConfiguration struct {
	// Allow is a list of allowed session types (e.g., "default", "admin") (SESSION MODE)
	Allow []string

	// Block is a list of blocked session types (e.g., "default", "guest") (SESSION MODE)
	Block []string

	// Permissions is a list of permissions required for the session (PBAC)
	Permissions *[]rbac.Permission

	// Roles is a list of roles required for the session (PBAC)
	Roles *[]string

	// SessionRequired is a flag to indicate if the session is required
	// defaults to true (Security best practice)
	SessionRequired bool

	// ManualResponse is a flag to indicate if the response should be handled manually
	// defaults to false
	ManualResponse bool

	// RequireCsrf is a flag to indicate if CSRF is required (Default: true)
	RequireCsrf bool
}
