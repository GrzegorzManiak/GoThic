package rbac

const (
	PermissionCreate   = "create"
	PermissionRead     = "read"
	PermissionUpdate   = "update"
	PermissionDelete   = "delete"
	PermissionList     = "list"
	PermissionExecute  = "execute"
	PermissionUpload   = "upload"
	PermissionDownload = "download"
	PermissionAll      = "all" // - Special permission that allows all actions on a resource
)

type Permission struct {
	Resource string `json:"resource" validate:"required,min=1,max=100"`
	Action   string `json:"action" validate:"required,min=1,max=50"`
}

func (p *Permission) IsValid() bool {
	if p.Resource == "" || p.Action == "" {
		return false
	}

	if p.Resource == PermissionAll {
		// - If the resource is "all", it can be used with any action.
		return true
	}

	switch p.Action {
	case PermissionCreate, PermissionRead, PermissionUpdate, PermissionDelete,
		PermissionList, PermissionExecute, PermissionUpload, PermissionDownload:
		return true
	default:
		return false
	}
}
