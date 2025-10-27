package rbac

import (
	"context"
	"testing"
)

func TestRoleCheck(t *testing.T) {
	tests := []struct {
		name            string
		subjectRoles    []string
		routeRolesList  map[string]bool
		routeRbacPolicy RouteRbacPolicy
		want            bool
	}{
		{
			name:            "Empty required roles should grant access",
			subjectRoles:    []string{"user"},
			routeRolesList:  map[string]bool{},
			routeRbacPolicy: PermissionsOrRole,
			want:            true,
		},
		{
			name:            "PermissionsOrRole - Has one required role",
			subjectRoles:    []string{"user", "admin"},
			routeRolesList:  map[string]bool{"admin": true},
			routeRbacPolicy: PermissionsOrRole,
			want:            true,
		},
		{
			name:            "PermissionsOrRole - No matching role",
			subjectRoles:    []string{"user"},
			routeRolesList:  map[string]bool{"admin": true},
			routeRbacPolicy: PermissionsOrRole,
			want:            false,
		},
		{
			name:            "PermissionsOrAllRoles - Has all required roles",
			subjectRoles:    []string{"user", "admin", "manager"},
			routeRolesList:  map[string]bool{"admin": true, "manager": true},
			routeRbacPolicy: PermissionsOrAllRoles,
			want:            true,
		},
		{
			name:            "PermissionsOrAllRoles - Missing one required role",
			subjectRoles:    []string{"user", "admin"},
			routeRolesList:  map[string]bool{"admin": true, "manager": true},
			routeRbacPolicy: PermissionsOrAllRoles,
			want:            false,
		},
		{
			name:            "Unknown policy should deny access",
			subjectRoles:    []string{"admin"},
			routeRolesList:  map[string]bool{"admin": true},
			routeRbacPolicy: RouteRbacPolicy(999),
			want:            false,
		},
		{
			name:            "PermissionsAndRole - Has one required role", // Explicitly test 'AND' policy
			subjectRoles:    []string{"user", "admin"},
			routeRolesList:  map[string]bool{"admin": true, "manager": true},
			routeRbacPolicy: PermissionsAndRole,
			want:            true, // Should be true since it only requires one
		},
		{
			name:            "PermissionsAndAllRoles - Has all required roles", // Explicitly test 'AND ALL' policy
			subjectRoles:    []string{"user", "admin", "manager"},
			routeRolesList:  map[string]bool{"admin": true, "manager": true},
			routeRbacPolicy: PermissionsAndAllRoles,
			want:            true,
		},
		{
			name:            "PermissionsAndAllRoles - Missing one required role",
			subjectRoles:    []string{"user", "admin"},
			routeRolesList:  map[string]bool{"admin": true, "manager": true},
			routeRbacPolicy: PermissionsAndAllRoles,
			want:            false,
		},
		{
			name:            "Edge Case - Subject has no roles, but roles are required",
			subjectRoles:    []string{},
			routeRolesList:  map[string]bool{"admin": true},
			routeRbacPolicy: PermissionsOrRole,
			want:            false,
		},
		{
			name:            "Edge Case - Subject has no roles, ALL roles are required",
			subjectRoles:    []string{},
			routeRolesList:  map[string]bool{"admin": true, "manager": true},
			routeRbacPolicy: PermissionsOrAllRoles,
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := roleCheck(tt.subjectRoles, tt.routeRolesList, tt.routeRbacPolicy)
			if got != tt.want {
				t.Errorf("roleCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPermissions(t *testing.T) {
	ctx := context.Background()
	mockManager := &mockRbacManager{}

	tests := []struct {
		name                string
		subjectIdentifier   string
		requiredPermissions *Permission
		requiredRoles       map[string]bool
		policy              RouteRbacPolicy
		want                bool
		wantErr             bool
	}{
		{
			name:              "No required permissions or roles - Should grant access ",
			subjectIdentifier: "admin-user",
			policy:            PermissionsOrRole,
			want:              true,
			wantErr:           false,
		},
		{
			name:                "Error - Manager fails to fetch subject data",
			subjectIdentifier:   "user-with-error", // Simulates a non existent user
			policy:              PermissionsOrRole,
			requiredPermissions: readWrite,
			want:                false,
			wantErr:             true,
		},
		{
			name:                "PermissionsOrRole - Succeeds on role alone (short-circuits)",
			subjectIdentifier:   "admin-user", // Has 'admin' role
			requiredPermissions: readWrite,    // User does NOT have this directly
			requiredRoles:       map[string]bool{"admin": true},
			policy:              PermissionsOrRole,
			want:                true, // Should return true immediately after role check
			wantErr:             false,
		},
		{
			name:                "PermissionsAndRole - Has role but fails on permission",
			subjectIdentifier:   "admin-user",      // Has 'admin' role, and direct readOnly
			requiredPermissions: NewPermission(99), // A permission the user doesn't have
			requiredRoles:       map[string]bool{"admin": true},
			policy:              PermissionsAndRole,
			want:                false, // Role check passes, permission check fails
			wantErr:             false,
		},
		{
			name:                "Permissions check - Succeeds via role permissions, not direct",
			subjectIdentifier:   "readonly-user",   // Has no direct permissions
			requiredPermissions: readOnly,          // This permission comes from the 'user' role
			requiredRoles:       map[string]bool{}, // No roles required
			policy:              PermissionsOrRole,
			want:                true, // Should pass after merging role permissions
			wantErr:             false,
		},
		{
			name:                "PermissionsAndAllRoles - Succeeds with role and permission",
			subjectIdentifier:   "admin-user", // Has 'admin' role
			requiredPermissions: readWrite,    // Gains this from 'admin' role
			requiredRoles:       map[string]bool{"admin": true},
			policy:              PermissionsAndAllRoles,
			want:                true,
			wantErr:             false,
		},
		{
			name:                "PermissionsAndAllRoles - Fails with multiple roles required",
			subjectIdentifier:   "admin-user", // Only has 'admin' role
			requiredPermissions: readOnly,
			requiredRoles:       map[string]bool{"admin": true, "superadmin": true},
			policy:              PermissionsAndAllRoles,
			want:                false, // Fails the 'AllRoles' check
			wantErr:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPermissions(
				ctx,
				mockManager,
				tt.subjectIdentifier,
				"",
				tt.requiredPermissions,
				tt.requiredRoles,
				tt.policy,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}
