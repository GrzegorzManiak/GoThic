package main

import (
	"context"
	"github.com/grzegorzmaniak/gothic/rbac"
)

type MyRbacManager struct {
	rbac.DefaultRBACManager
}

func (rm *MyRbacManager) GetSubjectRolesAndPermissions(ctx context.Context, subjectIdentifier string) (permissions rbac.Permissions, roles *[]string, err error) {
	return rbac.Permissions{
		"resource1": rbac.Read,
	}, &[]string{"example"}, nil
}

func (rm *MyRbacManager) GetRolePermissions(ctx context.Context, roleIdentifier string) (rbac.Permissions, error) {
	return rbac.Permissions{
		"session_data": rbac.Read | rbac.Create,
	}, nil
}
