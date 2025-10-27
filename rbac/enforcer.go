package rbac

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// roleCheck checks if the subject is a member of at least one of the roles in routeRolesList.
func roleCheck(subjectRoles []string, routeRolesList map[string]bool, routeRbacPolicy RouteRbacPolicy) bool {
	// - If no roles are required, access is granted.
	if len(routeRolesList) == 0 {
		return true
	}

	switch routeRbacPolicy {
	// - Check if the subject has any of the required roles.
	case PermissionsOrRole,
		PermissionsAndRole:
		for _, subjectRole := range subjectRoles {
			if _, found := routeRolesList[subjectRole]; found {
				return true
			}
		}

	// - Check if the subject has all the required roles.
	case PermissionsOrAllRoles,
		PermissionsAndAllRoles:
		for requiredRole := range routeRolesList {
			roleFound := false
			for _, subjectRole := range subjectRoles {
				if subjectRole == requiredRole {
					roleFound = true
					break
				}
			}

			// - If any required role is not found in the subject's roles, access is denied.
			if !roleFound {
				return false
			}
		}

		// - All required roles are found in the subject's roles, access is granted.
		return true

	default:
		zap.L().Warn("Unknown RBAC policy", zap.Int("policy", int(routeRbacPolicy)))
		return false // - If the policy is unknown, deny access.
	}

	// - If none of the required roles are found in the subject's roles, access is denied.
	return false
}

// mergeRolePermissions fetches permissions for each role in subjectRoles and merges them into a single Permissions map.
func mergeRolePermissions(ctx context.Context, subjectRoles []string, rbacManager Manager) (*Permission, error) {
	mergedPermissions := Permissions{}
	for _, role := range subjectRoles {
		rolePerms, err := GetRolePermissions(ctx, role, rbacManager)
		if err != nil {
			return nil, fmt.Errorf("failed to get permissions for role '%s': %w", role, err)
		}

		if rolePerms != nil {
			mergedPermissions = append(mergedPermissions, *rolePerms...)
		}
	}
	return mergedPermissions.Flatten(), nil
}

// CheckPermissions verifies if a subject meets the required permissions and/or roles
// as defined by an API configuration.
func CheckPermissions(
	ctx context.Context,
	rbacManager Manager,
	subjectIdentifier string,
	rbacCacheId string,
	requiredPermissions *Permission,
	requiredRoles map[string]bool,
	policy RouteRbacPolicy,
) (bool, error) {

	// - If no permissions or roles are required, access is granted.
	if len(requiredRoles) == 0 && requiredPermissions == nil {
		return true, nil
	}

	// - Fetch subject's roles and direct permissions
	subjectPermissions, subjectRoles, err := FetchSubjectRolesAndPermissions(ctx, subjectIdentifier, rbacCacheId, rbacManager)
	if err != nil {
		return false, fmt.Errorf("failed to fetch subject roles/permissions for '%s': %w", subjectIdentifier, err)
	}

	if subjectPermissions == nil {
		subjectPermissions = &Permission{}
	}

	if subjectRoles == nil {
		subjectRoles = &[]string{}
	}

	// - Check roles
	hasRole := roleCheck(*subjectRoles, requiredRoles, policy)
	switch policy {
	case PermissionsOrRole, PermissionsOrAllRoles:
		if hasRole {
			// - The roleCheck function already accounts for the RBAC policy. If the policy
			//   allows access with a role and the subject has it, we can return early.
			return true, nil
		}

	case PermissionsAndRole, PermissionsAndAllRoles:
		if !hasRole {
			// - If the policy requires a role and the subject does not have it, access is denied.
			return false, nil
		}
	}

	// - Check direct permissions
	hasDirect := subjectPermissions.Has(requiredPermissions)

	// - 1. Check for direct permissions first. If they exist, the permission requirement is met.
	if hasDirect {
		return true, nil
	}

	// - 2. If no direct permissions, merge permissions from all of the subject's roles.
	merged, err := mergeRolePermissions(ctx, *subjectRoles, rbacManager)
	if err != nil {
		return false, err
	}

	// - 3. Check if the merged role permissions satisfy the requirement.
	return merged.Has(requiredPermissions), nil
}
