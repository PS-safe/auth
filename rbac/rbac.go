// Package rbac defines roles and a small role→permissions map.
//
// Keep this file simple and obvious. A real production RBAC eventually needs
// dynamic roles, per-resource permissions, and policy inheritance — but for
// most internal apps a static map is enough and the maintenance cost stays
// near zero.
package rbac

// Role is a coarse identity tag attached to a User.
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// Permission is a verb-noun the caller checks for.
type Permission string

const (
	PermReadSelf    Permission = "self:read"
	PermReadUsers   Permission = "users:read"
	PermWriteUsers  Permission = "users:write"
	PermReadAdmin   Permission = "admin:read"
	PermWriteAdmin  Permission = "admin:write"
)

var rolePerms = map[Role]map[Permission]struct{}{
	RoleUser: {
		PermReadSelf: {},
	},
	RoleAdmin: {
		PermReadSelf:    {},
		PermReadUsers:   {},
		PermWriteUsers:  {},
		PermReadAdmin:   {},
		PermWriteAdmin:  {},
	},
}

// Has returns true if role grants perm.
func Has(role Role, perm Permission) bool {
	perms, ok := rolePerms[role]
	if !ok {
		return false
	}
	_, granted := perms[perm]
	return granted
}

// AllPermissions returns the permission set for a role (useful for tokens
// that need to embed claims).
func AllPermissions(role Role) []Permission {
	perms, ok := rolePerms[role]
	if !ok {
		return nil
	}
	out := make([]Permission, 0, len(perms))
	for p := range perms {
		out = append(out, p)
	}
	return out
}
