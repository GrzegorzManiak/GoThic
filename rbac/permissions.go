package rbac

import (
	"encoding/base64"
	"math/big"
)

// Permission represents a set of permissions using a bitmask
type Permission big.Int

func NewPermission(permission uint64) *Permission {
	b := big.NewInt(0)
	b.SetBit(b, int(permission), 1)
	return (*Permission)(b)
}

func (p *Permission) Set(bit int) {
	(*big.Int)(p).SetBit((*big.Int)(p), bit, 1)
}

func (p *Permission) Unset(bit int) {
	(*big.Int)(p).SetBit((*big.Int)(p), bit, 0)
}

func (p *Permission) Has(permission *Permission) bool {
	// - Create a new big.Int to store the result of the AND operation.
	result := new(big.Int)

	// - Perform the AND, storing the result in the new variable.
	result.And((*big.Int)(p), (*big.Int)(permission))

	// - Compare the result with the required permissions.
	return result.Cmp((*big.Int)(permission)) == 0
}

func (p *Permission) And(other *Permission) *Permission {
	return (*Permission)(new(big.Int).And((*big.Int)(p), (*big.Int)(other)))
}

func (p *Permission) Or(other *Permission) *Permission {
	return (*Permission)(new(big.Int).Or((*big.Int)(p), (*big.Int)(other)))
}

func (p *Permission) Serialize() string {
	// - Convert the big.Int to a byte slice.
	bytes := (*big.Int)(p).Bytes()

	// - Encode the byte slice to a base64 string.
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func DeserializePermission(encoded string) (*Permission, error) {
	// - Decode the base64 string to a byte slice.
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	// - Create a new big.Int from the byte slice.
	b := new(big.Int).SetBytes(bytes)

	// - Return a new Permission pointer.
	return (*Permission)(b), nil
}

// Permissions is a slice of Permission pointers, representing a collection of permissions
// It is only used to provide a more convenient interface for handling multiple permissions
// and then flattening them into a single Permission bitmask.
type Permissions []*Permission

func (ps Permissions) Flatten() *Permission {
	result := new(big.Int)
	for _, p := range ps {
		result.Or(result, (*big.Int)(p))
	}
	return (*Permission)(result)
}
