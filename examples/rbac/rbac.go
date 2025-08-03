package main

import (
	"context"
	"github.com/grzegorzmaniak/gothic/rbac"
)

var (
	ReadWriteSessionData = rbac.NewPermission(0)
	ReadOnlySessionData  = rbac.NewPermission(1)
)

type MyRbacManager struct {
	rbac.DefaultRBACManager
}

func (rm *MyRbacManager) GetSubjectRolesAndPermissions(ctx context.Context, subjectIdentifier string) (permissions *rbac.Permissions, roles *[]string, err error) {
	return &rbac.Permissions{
		ReadWriteSessionData,
		ReadOnlySessionData,
	}, &[]string{"test"}, nil
}

func (rm *MyRbacManager) GetRolePermissions(ctx context.Context, roleIdentifier string) (*rbac.Permissions, error) {
	return &rbac.Permissions{
		ReadWriteSessionData,
	}, nil
}
