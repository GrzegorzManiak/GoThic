package rbac

import (
	"math/big"
	"testing"
)

func TestNewPermission(t *testing.T) {
	t.Run("Create permission with bit 0", func(t *testing.T) {
		perm := NewPermission(0)
		if perm == nil {
			t.Fatal("Expected non-nil permission")
		}
		expected := big.NewInt(1) // 2^0 = 1
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(perm).String())
		}
	})

	t.Run("Create permission with bit 5", func(t *testing.T) {
		perm := NewPermission(5)
		expected := big.NewInt(32) // 2^5 = 32
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(perm).String())
		}
	})

	t.Run("Create permission with large bit", func(t *testing.T) {
		perm := NewPermission(100)
		if perm == nil {
			t.Fatal("Expected non-nil permission for large bit")
		}
		expected := new(big.Int).Lsh(big.NewInt(1), 100) // 2^100
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected large permission to be set correctly")
		}
	})
}

func TestPermissionSetUnset(t *testing.T) {
	t.Run("Set single bit", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(3)
		// Should have bits 0 and 3 set: 1 + 8 = 9
		expected := big.NewInt(9)
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(perm).String())
		}
	})

	t.Run("Set multiple bits", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(1)
		perm.Set(2)
		perm.Set(4)
		// Bits 0, 1, 2, 4 = 1 + 2 + 4 + 16 = 23
		expected := big.NewInt(23)
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(perm).String())
		}
	})

	t.Run("Unset bit", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(1)
		perm.Set(2)
		perm.Unset(1)
		// Bits 0, 2 = 1 + 4 = 5
		expected := big.NewInt(5)
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(perm).String())
		}
	})

	t.Run("Unset already unset bit", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Unset(5)
		expected := big.NewInt(1)
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(perm).String())
		}
	})
}

func TestPermissionHas(t *testing.T) {
	t.Run("Has single permission", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(1)
		perm.Set(2)

		check := NewPermission(1)
		if !perm.Has(check) {
			t.Error("Expected permission to have bit 1")
		}
	})

	t.Run("Does not have permission", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(1)

		check := NewPermission(5)
		if perm.Has(check) {
			t.Error("Expected permission to not have bit 5")
		}
	})

	t.Run("Has multiple permissions", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(1)
		perm.Set(2)
		perm.Set(3)

		check := NewPermission(1)
		check.Set(2)
		if !perm.Has(check) {
			t.Error("Expected permission to have bits 1 and 2")
		}
	})

	t.Run("Partial permission match returns false", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(1)

		check := NewPermission(1)
		check.Set(2)
		if perm.Has(check) {
			t.Error("Expected permission to not fully match (missing bit 2)")
		}
	})
}

func TestPermissionAnd(t *testing.T) {
	t.Run("AND with overlapping bits", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm1.Set(1)
		perm1.Set(2)

		perm2 := NewPermission(1)
		perm2.Set(3)

		result := perm1.And(perm2)
		// Only bit 1 is common: value = 2
		expected := big.NewInt(2)
		if (*big.Int)(result).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(result).String())
		}
	})

	t.Run("AND with no overlapping bits", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm2 := NewPermission(1)

		result := perm1.And(perm2)
		expected := big.NewInt(0)
		if (*big.Int)(result).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(result).String())
		}
	})

	t.Run("AND with identical permissions", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm1.Set(1)
		perm1.Set(2)

		perm2 := NewPermission(0)
		perm2.Set(1)
		perm2.Set(2)

		result := perm1.And(perm2)
		if (*big.Int)(result).Cmp((*big.Int)(perm1)) != 0 {
			t.Error("Expected AND of identical permissions to equal original")
		}
	})
}

func TestPermissionOr(t *testing.T) {
	t.Run("OR combines different bits", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm1.Set(1)

		perm2 := NewPermission(2)
		perm2.Set(3)

		result := perm1.Or(perm2)
		// Bits 0, 1, 2, 3 = 1 + 2 + 4 + 8 = 15
		expected := big.NewInt(15)
		if (*big.Int)(result).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(result).String())
		}
	})

	t.Run("OR with overlapping bits", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm1.Set(1)

		perm2 := NewPermission(1)
		perm2.Set(2)

		result := perm1.Or(perm2)
		// Bits 0, 1, 2 = 1 + 2 + 4 = 7
		expected := big.NewInt(7)
		if (*big.Int)(result).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(result).String())
		}
	})

	t.Run("OR with zero permission", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm1.Set(1)

		perm2 := new(Permission)
		(*big.Int)(perm2).SetInt64(0)

		result := perm1.Or(perm2)
		if (*big.Int)(result).Cmp((*big.Int)(perm1)) != 0 {
			t.Error("Expected OR with zero to equal original")
		}
	})
}

func TestPermissionMarshalUnmarshal(t *testing.T) {
	t.Run("Marshal and unmarshal simple permission", func(t *testing.T) {
		perm := NewPermission(5)
		perm.Set(10)

		data, err := perm.MarshalBinary()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}
		if data == nil {
			t.Fatal("Expected non-nil marshaled data")
		}

		restored := new(Permission)
		err = restored.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if (*big.Int)(restored).Cmp((*big.Int)(perm)) != 0 {
			t.Error("Unmarshaled permission does not match original")
		}
	})

	t.Run("Marshal nil permission returns error", func(t *testing.T) {
		var perm *Permission
		_, err := perm.MarshalBinary()
		if err == nil {
			t.Error("Expected error when marshaling nil permission")
		}
	})

	t.Run("Unmarshal into nil permission returns error", func(t *testing.T) {
		var perm *Permission
		err := perm.UnmarshalBinary([]byte{1, 2, 3})
		if err == nil {
			t.Error("Expected error when unmarshaling into nil permission")
		}
	})

	t.Run("Marshal and unmarshal zero permission", func(t *testing.T) {
		perm := new(Permission)
		(*big.Int)(perm).SetInt64(0)

		data, err := perm.MarshalBinary()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		restored := new(Permission)
		err = restored.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if (*big.Int)(restored).Cmp((*big.Int)(perm)) != 0 {
			t.Error("Unmarshaled zero permission does not match")
		}
	})

	t.Run("Marshal and unmarshal large permission", func(t *testing.T) {
		perm := NewPermission(100)
		perm.Set(200)
		perm.Set(300)

		data, err := perm.MarshalBinary()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		restored := new(Permission)
		err = restored.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if (*big.Int)(restored).Cmp((*big.Int)(perm)) != 0 {
			t.Error("Unmarshaled large permission does not match original")
		}
	})
}

func TestPermissionSerializeDeserialize(t *testing.T) {
	t.Run("Serialize and deserialize simple permission", func(t *testing.T) {
		perm := NewPermission(3)
		perm.Set(7)

		serialized := perm.Serialize()
		if serialized == "" {
			t.Fatal("Expected non-empty serialized string")
		}

		restored, err := DeserializePermission(serialized)
		if err != nil {
			t.Fatalf("Deserialize failed: %v", err)
		}

		if (*big.Int)(restored).Cmp((*big.Int)(perm)) != 0 {
			t.Error("Deserialized permission does not match original")
		}
	})

	t.Run("Serialize zero permission", func(t *testing.T) {
		perm := new(Permission)
		(*big.Int)(perm).SetInt64(0)

		serialized := perm.Serialize()
		// Zero permission should serialize to empty or minimal representation
		if serialized == "" {
			// Empty is acceptable for zero
			return
		}

		restored, err := DeserializePermission(serialized)
		if err != nil {
			t.Fatalf("Deserialize failed: %v", err)
		}

		if (*big.Int)(restored).Cmp((*big.Int)(perm)) != 0 {
			t.Error("Deserialized zero permission does not match")
		}
	})

	t.Run("Deserialize invalid base64 returns error", func(t *testing.T) {
		_, err := DeserializePermission("not-valid-base64!!!")
		if err == nil {
			t.Error("Expected error when deserializing invalid base64")
		}
	})

	t.Run("Deserialize empty string", func(t *testing.T) {
		// Empty string decodes to empty byte slice, which should create zero permission
		perm, err := DeserializePermission("")
		if err != nil {
			t.Fatalf("Expected no error for empty string, got %v", err)
		}
		if perm == nil {
			t.Fatal("Expected non-nil permission")
		}
		expected := big.NewInt(0)
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected zero permission, got %s", (*big.Int)(perm).String())
		}
	})

	t.Run("Serialize nil permission returns empty string", func(t *testing.T) {
		var perm *Permission
		serialized := perm.Serialize()
		if serialized != "" {
			t.Errorf("Expected empty string for nil permission, got %s", serialized)
		}
	})

	t.Run("Round-trip large permission", func(t *testing.T) {
		perm := NewPermission(50)
		perm.Set(100)
		perm.Set(150)
		perm.Set(200)

		serialized := perm.Serialize()
		restored, err := DeserializePermission(serialized)
		if err != nil {
			t.Fatalf("Deserialize failed: %v", err)
		}

		if (*big.Int)(restored).Cmp((*big.Int)(perm)) != 0 {
			t.Error("Round-trip large permission does not match")
		}
	})
}

func TestPermissionsFlatten(t *testing.T) {
	t.Run("Flatten single permission", func(t *testing.T) {
		perms := Permissions{NewPermission(0)}
		flattened := perms.Flatten()

		expected := big.NewInt(1)
		if (*big.Int)(flattened).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(flattened).String())
		}
	})

	t.Run("Flatten multiple non-overlapping permissions", func(t *testing.T) {
		perms := Permissions{
			NewPermission(0),
			NewPermission(1),
			NewPermission(2),
		}
		flattened := perms.Flatten()

		// Bits 0, 1, 2 = 1 + 2 + 4 = 7
		expected := big.NewInt(7)
		if (*big.Int)(flattened).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(flattened).String())
		}
	})

	t.Run("Flatten overlapping permissions", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm1.Set(1)

		perm2 := NewPermission(1)
		perm2.Set(2)

		perms := Permissions{perm1, perm2}
		flattened := perms.Flatten()

		// Bits 0, 1, 2 = 1 + 2 + 4 = 7
		expected := big.NewInt(7)
		if (*big.Int)(flattened).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(flattened).String())
		}
	})

	t.Run("Flatten empty permissions", func(t *testing.T) {
		perms := Permissions{}
		flattened := perms.Flatten()

		expected := big.NewInt(0)
		if (*big.Int)(flattened).Cmp(expected) != 0 {
			t.Errorf("Expected %s for empty permissions, got %s", expected.String(), (*big.Int)(flattened).String())
		}
	})

	t.Run("Flatten complex permissions", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm1.Set(2)
		perm1.Set(4)

		perm2 := NewPermission(1)
		perm2.Set(3)
		perm2.Set(5)

		perm3 := NewPermission(6)
		perm3.Set(7)

		perms := Permissions{perm1, perm2, perm3}
		flattened := perms.Flatten()

		// Bits 0,1,2,3,4,5,6,7 = 1+2+4+8+16+32+64+128 = 255
		expected := big.NewInt(255)
		if (*big.Int)(flattened).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(flattened).String())
		}
	})

	t.Run("Flatten with nil permission in slice", func(t *testing.T) {
		perm1 := NewPermission(0)
		var nilPerm *Permission
		perm2 := NewPermission(2)

		perms := Permissions{perm1, nilPerm, perm2}
		flattened := perms.Flatten()

		// Should handle nil gracefully, bits 0 and 2 = 1 + 4 = 5
		expected := big.NewInt(5)
		if (*big.Int)(flattened).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(flattened).String())
		}
	})
}

func TestPermissionEdgeCases(t *testing.T) {
	t.Run("Permission operations are chainable", func(t *testing.T) {
		perm1 := NewPermission(0)
		perm2 := NewPermission(1)
		perm3 := NewPermission(2)

		result := perm1.Or(perm2).Or(perm3)
		// Bits 0, 1, 2 = 7
		expected := big.NewInt(7)
		if (*big.Int)(result).Cmp(expected) != 0 {
			t.Errorf("Expected chainable operations to work, got %s", (*big.Int)(result).String())
		}
	})

	t.Run("Setting same bit multiple times", func(t *testing.T) {
		perm := NewPermission(0)
		perm.Set(1)
		perm.Set(1)
		perm.Set(1)

		// Should still only have bits 0 and 1: 1 + 2 = 3
		expected := big.NewInt(3)
		if (*big.Int)(perm).Cmp(expected) != 0 {
			t.Errorf("Expected %s, got %s", expected.String(), (*big.Int)(perm).String())
		}
	})

	t.Run("Very large bit numbers", func(t *testing.T) {
		perm := NewPermission(1000)
		if perm == nil {
			t.Fatal("Expected permission with bit 1000 to be created")
		}

		check := NewPermission(1000)
		if !perm.Has(check) {
			t.Error("Expected permission to have bit 1000")
		}
	})
}
