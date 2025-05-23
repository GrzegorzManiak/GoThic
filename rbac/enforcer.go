package rbac

import (
	"context"
	"fmt"
)

// checkAllPermissions checks if all permissions in requiredPerms are present in availablePerms.
func checkAllPermissions(availablePerms []Permission, requiredPerms []Permission) bool {
	// - If no permissions are required, access is granted.
	if len(requiredPerms) == 0 {
		return true
	}

	// - If there are more required permissions than available permissions,
	if len(availablePerms) < len(requiredPerms) {
		return false
	}

	// - For efficient lookup, convert availablePerms to a map (acting as a set).
	availableSet := make(map[Permission]bool, len(availablePerms))
	for _, p := range availablePerms {
		availableSet[p] = true
	}

	// - Check if all required permissions are present in the available set.
	for _, reqP := range requiredPerms {
		if !availableSet[reqP] {
			return false
		}
	}

	// - If all required permissions are found in the available set, access is granted.
	return true
}

// checkAnyRole checks if the subject is a member of at least one of the roles in requiredRolesList.
func checkAnyRole(subjectActualRoles []string, requiredRolesList []string) bool {
	// - If no roles are required, access is granted.
	if len(requiredRolesList) == 0 {
		return false
	}

	// - If the subject has no roles, they cannot match any role in the required list.
	if len(subjectActualRoles) == 0 {
		return false
	}

	// - For efficient lookup, convert subjectActualRoles to a map (acting as a set).
	subjectRolesSet := make(map[string]bool, len(subjectActualRoles))
	for _, r := range subjectActualRoles {
		subjectRolesSet[r] = true
	}

	// - Check if the subject has at least one of the required roles.
	for _, reqR := range requiredRolesList {
		if subjectRolesSet[reqR] {
			return true
		}
	}

	// - If none of the required roles are found in the subject's roles, access is denied.
	return false
}

// CheckPermissions verifies if a subject meets the required permissions and/or roles
// as defined by an API configuration.
func CheckPermissions(
	ctx context.Context,
	rbacManager Manager,
	subjectIdentifier string,
	rbacCacheId string,
	apiConfigRequiredPermissions *[]Permission,
	apiConfigRequiredRoles *[]string,
) (bool, error) {

	// - Prevent nil pointer dereference
	var requiredPerms []Permission
	if apiConfigRequiredPermissions != nil {
		requiredPerms = *apiConfigRequiredPermissions
	}

	var requiredRolesFromConfig []string
	if apiConfigRequiredRoles != nil {
		requiredRolesFromConfig = *apiConfigRequiredRoles
	}

	// - If the API configuration requires no specific permissions AND no specific roles
	// for this particular RBAC check, then this check is considered passed
	if len(requiredPerms) == 0 && len(requiredRolesFromConfig) == 0 {
		return true, nil
	}

	// - Fetch subject's actual direct permissions and their actual assigned roles ONCE.
	subjectDirectPermissions, subjectAssignedRoles, err := FetchSubjectRolesAndPermissions(ctx, subjectIdentifier, rbacCacheId, rbacManager)
	if err != nil {
		return false, fmt.Errorf("failed to fetch subject's roles and direct permissions for '%s': %w", subjectIdentifier, err)
	}

	// - Ensure slices are not nil for easier handling, even if empty.
	if subjectDirectPermissions == nil {
		subjectDirectPermissions = &[]Permission{}
	}

	if subjectAssignedRoles == nil {
		subjectAssignedRoles = &[]string{}
	}

	// - Subject has ANY of the roles specified as sufficient by the API config
	if checkAnyRole(*subjectAssignedRoles, requiredRolesFromConfig) {
		return true, nil
	}

	// - Subject directly has ALL required permissions
	if checkAllPermissions(*subjectDirectPermissions, requiredPerms) {
		return true, nil
	}

	// - Combined permissions from ALL the subject's assigned roles
	hasAnyPermissions := len(*subjectAssignedRoles) > 0 && len(*subjectDirectPermissions) > 0
	if len(requiredPerms) == 0 || !hasAnyPermissions {
		return false, nil
	}

	allPermissionsFromSubjectRolesSet := make(map[Permission]bool)

	for _, subjectRoleName := range *subjectAssignedRoles {
		permissionsForOneRole, rolePermErr := GetRolePermissions(ctx, subjectRoleName, rbacManager)
		if rolePermErr != nil {
			return false, fmt.Errorf("failed to get permissions for role '%s': %w", subjectRoleName, rolePermErr)
		}

		if permissionsForOneRole == nil {
			continue
		}

		for _, p := range *permissionsForOneRole {
			allPermissionsFromSubjectRolesSet[p] = true
		}
	}

	for _, p := range *subjectDirectPermissions {
		allPermissionsFromSubjectRolesSet[p] = true
	}

	// - Convert the set of collected permissions from roles to a slice.
	effectivePermissions := make([]Permission, 0, len(allPermissionsFromSubjectRolesSet))
	for p := range allPermissionsFromSubjectRolesSet {
		effectivePermissions = append(effectivePermissions, p)
	}

	// - Check if this combined set of permissions from the subject's roles contains all required permissions.
	if checkAllPermissions(effectivePermissions, requiredPerms) {
		return true, nil
	}

	return false, nil
}
