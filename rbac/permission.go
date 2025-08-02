package rbac

type ActionBits uint16

const (
	Create ActionBits = 1 << iota
	Read
	Update
	Delete
	List
	Execute
	Upload
	Download
	All = Create | Read | Update | Delete |
		List | Execute | Upload | Download
)

type Permissions map[string]ActionBits
