package main

import (
	"context"
	"github.com/grzegorzmaniak/gothic/rbac"
)

type MyRbacManager struct {
	rbac.DefaultRBACManager
}

func (rm *MyRbacManager) GetSubjectRolesAndPermissions(ctx context.Context, subjectIdentifier string) (permissions *[]rbac.Permission, roles *[]string, err error) {
	return &[]rbac.Permission{
		{Action: rbac.PermissionRead, Resource: "resource1"},
	}, &[]string{"example"}, nil
}

func (rm *MyRbacManager) GetRolePermissions(ctx context.Context, roleIdentifier string) (*[]rbac.Permission, error) {
	return &[]rbac.Permission{
		{Action: rbac.PermissionRead, Resource: "session_data"},
	}, nil
}
