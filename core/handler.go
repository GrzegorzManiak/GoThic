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

// APIConfiguration defines the configuration for an API route.
//
// RbacPolicy defaults to rbac.PermissionsOrRole, which means that either permissions or roles are required for access.
//
// Allow and Block are used to define session types that are allowed or blocked for this route; Allow takes precedence over Block,
// meaning that if a session type is in both Allow and Block, it will be allowed. Allow acts as a whitelist, while Block acts as a blacklist.
//
// SessionRequired defaults to true, meaning that a session is required for this route. There is no requirement on the session type, so
// it can be any session type that is allowed by the Allow / Block lists.
//
// ManualResponse defaults to false, meaning that the response is handled automatically by the framework. If set to true, the handler
// is responsible for handling the response manually.
//
// RequireCsrf defaults to true, meaning that CSRF protection is required for this route. If set to false, CSRF protection is not required.
type APIConfiguration struct {
	// Allow is a list of allowed session types (e.g., "default", "admin") (SESSION MODE)
	Allow []string

	// Block is a list of blocked session types (e.g., "default", "guest") (SESSION MODE)
	Block []string

	// Permissions is a list of permissions required for the session (PBAC)
	Permissions rbac.Permissions

	// Roles is a list of roles required for the session (PBAC)
	Roles *[]string

	// RbacPolicy defines the RBAC policy to be used for this route
	RbacPolicy rbac.RouteRbacPolicy

	// SessionRequired is a flag to indicate if the session is required
	// defaults to true (Security best practice)
	SessionRequired bool

	// ManualResponse is a flag to indicate if the response should be handled manually
	// defaults to false
	ManualResponse bool

	// RequireCsrf is a flag to indicate if CSRF is required (Default: true)
	RequireCsrf bool

	// flatRoles is a cached map of roles for this configuration, It provides a quick lookup for roles
	flatRoles map[string]bool

	// flatPermissions is a cached map of permissions for this configuration, It provides a quick lookup for permissions
	flatPermissions            rbac.Permission
	flatPermissionsInitialized bool
}

func (config *APIConfiguration) GetFlatRoles() map[string]bool {
	if config.flatRoles == nil {
		config.flatRoles = make(map[string]bool)
		if config.Roles != nil {
			for _, role := range *config.Roles {
				config.flatRoles[role] = true
			}
		}
	}
	return config.flatRoles
}

func (config *APIConfiguration) GetFlatPermissions() *rbac.Permission {
	if !config.flatPermissionsInitialized {
		config.flatPermissionsInitialized = true
		config.flatPermissions = *config.Permissions.Flatten()
	}
	return &config.flatPermissions
}
