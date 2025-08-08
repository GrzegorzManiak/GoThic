package rbac

import (
	"encoding/base64"
	"errors"
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

// MarshalBinary implements the encoding.BinaryMarshaler interface.
// It returns the raw byte representation of the permission's big.Int.
func (p *Permission) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("cannot marshal nil Permission")
	}
	return (*big.Int)(p).Bytes(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// It sets the permission's big.Int from a raw byte slice.
func (p *Permission) UnmarshalBinary(data []byte) error {
	if p == nil {
		return errors.New("cannot unmarshal into nil Permission")
	}
	(*big.Int)(p).SetBytes(data)
	return nil
}

// Serialize returns the permission as a base64 encoded string for use in text-based formats like JSON.
func (p *Permission) Serialize() string {
	bytes, _ := p.MarshalBinary()
	if bytes == nil {
		return "" // - Handle nil case gracefully (e.g., no permissions set)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// DeserializePermission decodes a base64 string into a Permission.
func DeserializePermission(encoded string) (*Permission, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	p := new(Permission)
	if err := p.UnmarshalBinary(bytes); err != nil { // Reuse binary unmarshaler
		return nil, err
	}
	return p, nil
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
