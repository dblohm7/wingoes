// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package registry

import (
	"fmt"
	"slices"
	"testing"

	"golang.org/x/sys/windows/registry"
)

const testSubKey = `SOFTWARE\wingoes\Test`

var mismatchValues = map[uint32]any{
	registry.DWORD:     "junk",
	registry.QWORD:     ExpandString("junk%JUNK%"),
	registry.MULTI_SZ:  []byte{0x6A, 0x75, 0x6E, 0x6B},
	registry.SZ:        uint32(0x75757575),
	registry.EXPAND_SZ: []string{"world", "of", "junk"},
	registry.BINARY:    uint64(0x7777777755555555),
}

var values = []any{
	uint32(0x75757575),
	uint64(0x7777777755555555),
	[]string{"world", "of", "junk"},
	"junk",
	ExpandString("junk%JUNK%"),
	[]byte{0x6A, 0x75, 0x6E, 0x6B},
	"",
	[]byte{},
}

var stringTests = [...]string{
	"foo",
	"foo;%PATH%",
}

func TestSingleRegistryValueAccessors(t *testing.T) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, testSubKey, registry.WRITE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("Opening registry key: %v", err)
	}
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, testSubKey)
	})
	defer key.Close()

	t.Run("SetSingleRegistryValue", func(t *testing.T) { testSetSingleRegistryValue(t, key) })
	t.Run("GetSingleRegistryValue", func(t *testing.T) { testGetSingleRegistryValue(t, key) })
	t.Run("GetSingleRegistryValueTypeMismatch", func(t *testing.T) { testGetSingleRegistryValueTypeMismatch(t, key) })
	t.Run("Expansion", func(t *testing.T) { testExpansion(t, key) })
	t.Run("GetDWORDAsQWORD", func(t *testing.T) { testGetDWORDAsQWORD(t, key) })
}

func testSetSingleRegistryValue(t *testing.T, key registry.Key) {
	for _, rv := range values {
		valueName := fmt.Sprintf("Value%T", rv)
		switch v := rv.(type) {
		case uint32:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Errorf("Setting %q: %v", valueName, err)
			}
		case uint64:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Errorf("Setting %q: %v", valueName, err)
			}
		case []string:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Errorf("Setting %q: %v", valueName, err)
			}
		case string:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Errorf("Setting %q: %v", valueName, err)
			}
		case ExpandString:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Errorf("Setting %q: %v", valueName, err)
			}
		case []byte:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Errorf("Setting %q: %v", valueName, err)
			}
		default:
			t.Fatalf("Unknown type")
		}

		verifyValue(t, key, valueName, rv)
	}
}

func testGetSingleRegistryValue(t *testing.T, key registry.Key) {
	for _, rv := range values {
		var vAny any
		valueName := fmt.Sprintf("Value%T", rv)
		switch rv.(type) {
		case uint32:
			v, err := GetSingleRegistryValue[uint32](key, "", valueName)
			if err != nil {
				t.Errorf("GetSingleRegistryValue[%T] returned %v", v, err)
			}
			vAny = v
		case uint64:
			v, err := GetSingleRegistryValue[uint64](key, "", valueName)
			if err != nil {
				t.Errorf("GetSingleRegistryValue[%T] returned %v", v, err)
			}
			vAny = v
		case []string:
			v, err := GetSingleRegistryValue[[]string](key, "", valueName)
			if err != nil {
				t.Errorf("GetSingleRegistryValue[%T] returned %v", v, err)
			}
			vAny = v
		case string:
			v, err := GetSingleRegistryValue[string](key, "", valueName)
			if err != nil {
				t.Errorf("GetSingleRegistryValue[%T] returned %v", v, err)
			}
			vAny = v
		case ExpandString:
			v, err := GetSingleRegistryValue[string](key, "", valueName)
			if err != nil {
				t.Errorf("GetSingleRegistryValue[%T] returned %v", v, err)
			}
			vAny = ExpandString(v)
		case []byte:
			v, err := GetSingleRegistryValue[[]byte](key, "", valueName)
			if err != nil {
				t.Errorf("GetSingleRegistryValue[%T] returned %v", v, err)
			}
			vAny = v
		default:
			t.Fatalf("Unknown type")
		}

		verifyValue(t, key, valueName, vAny)
	}
}

func testGetSingleRegistryValueTypeMismatch(t *testing.T, key registry.Key) {
	for _, mmv := range mismatchValues {
		valueName := fmt.Sprintf("MismatchValue%T", mmv)
		switch v := any(mmv).(type) {
		case uint32:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Fatalf("SetSingleRegistryValue[%T] returned %v", v, err)
			}
		case uint64:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Fatalf("SetSingleRegistryValue[%T] returned %v", v, err)
			}
		case string:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Fatalf("SetSingleRegistryValue[%T] returned %v", v, err)
			}
		case ExpandString:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Fatalf("SetSingleRegistryValue[%T] returned %v", v, err)
			}
		case []string:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Fatalf("SetSingleRegistryValue[%T] returned %v", v, err)
			}
		case []byte:
			if err := SetSingleRegistryValue(key, "", valueName, v); err != nil {
				t.Fatalf("SetSingleRegistryValue[%T] returned %v", v, err)
			}
		default:
			t.Fatalf("Unknown type")
		}
	}

	for mmvt, mmv := range mismatchValues {
		valueName := fmt.Sprintf("MismatchValue%T", mmv)
		switch mmvt {
		case registry.DWORD:
			_, err := GetSingleRegistryValue[uint32](key, "", valueName)
			if err == nil {
				t.Errorf("Unexpected success retrieving %T as %T", mmv, uint32(0))
			}
		case registry.QWORD:
			_, err := GetSingleRegistryValue[uint64](key, "", valueName)
			if err == nil {
				t.Errorf("Unexpected success retrieving %T as %T", mmv, uint64(0))
			}
		case registry.MULTI_SZ:
			_, err := GetSingleRegistryValue[[]string](key, "", valueName)
			if err == nil {
				t.Errorf("Unexpected success retrieving %T as %T", mmv, []string{})
			}
		case registry.SZ, registry.EXPAND_SZ:
			_, err := GetSingleRegistryValue[string](key, "", valueName)
			if err == nil {
				t.Errorf("Unexpected success retrieving %T as %T", mmv, "")
			}
		case registry.BINARY:
			_, err := GetSingleRegistryValue[[]byte](key, "", valueName)
			if err == nil {
				t.Errorf("Unexpected success retrieving %T as %T", mmv, []byte{})
			}
		default:
			t.Fatalf("Unknown type")
		}
	}
}

func testExpansion(t *testing.T, key registry.Key) {
	const valueName = "TestExpansion"
	for _, regType := range []uint32{registry.SZ, registry.EXPAND_SZ} {
		for _, st := range stringTests {
			switch regType {
			case registry.SZ:
				if err := key.SetStringValue(valueName, st); err != nil {
					t.Fatalf("Setting registry value %q to %q", valueName, st)
				}
			case registry.EXPAND_SZ:
				if err := key.SetExpandStringValue(valueName, st); err != nil {
					t.Fatalf("Setting registry value %q to %q", valueName, st)
				}
			default:
				t.Fatalf("Invalid type 0x%08X", regType)
			}

			str, err := GetSingleRegistryValue[string](key, "", valueName)
			if err != nil {
				t.Errorf("GetSingleRegistryValue[string] error %v", err)
			}

			switch regType {
			case registry.SZ:
				if str != st {
					t.Errorf("GetSingleRegistryValue[string] value: got %q, want %q", str, st)
				}
			case registry.EXPAND_SZ:
				xsValue, xsType, err := key.GetStringValue(valueName)
				if err != nil {
					t.Fatalf("Getting registry value %q", st)
				}
				if xsType != regType {
					t.Fatalf("type mismatch: got 0x%08X, want 0x%08X", xsType, regType)
				}
				est, err := registry.ExpandString(xsValue)
				if err != nil {
					t.Fatalf("ExpandString: %v", err)
				}
				if str != est {
					t.Errorf("GetSingleRegistryValue[string] value: got %q, want %q", str, est)
				}
			default:
				t.Fatalf("Invalid type 0x%08X", regType)
			}
		}
	}
}

func testGetDWORDAsQWORD(t *testing.T, key registry.Key) {
	valueName := fmt.Sprintf("Value%T", values[0])
	v, err := GetSingleRegistryValue[uint64](key, "", valueName)
	if err != nil {
		t.Errorf("GetSingleRegistryValue[%T] error %v", v, err)
	}

	check := uint64(values[0].(uint32))
	if v != check {
		t.Errorf("Mismatch: got 0x%016X, want 0x%016X", v, check)
	}
}

func verifyValue(t *testing.T, key registry.Key, valueName string, value any) {
	switch v := value.(type) {
	case uint32:
		vv, vt, err := key.GetIntegerValue(valueName)
		if err != nil {
			t.Fatalf("GetIntegerValue(%q): %v", valueName, err)
		}
		if vt != registry.DWORD {
			t.Fatalf("GetIntegerValue(%q) type: got 0x%08X, want 0x%08X", valueName, vt, registry.DWORD)
		}
		if v != uint32(vv) {
			t.Errorf("Verifying %q: got %d, want %d", valueName, v, vv)
		}
	case uint64:
		vv, vt, err := key.GetIntegerValue(valueName)
		if err != nil {
			t.Fatalf("GetIntegerValue(%q): %v", valueName, err)
		}
		if vt != registry.QWORD {
			t.Fatalf("GetIntegerValue(%q) type: got 0x%08X, want 0x%08X", valueName, vt, registry.QWORD)
		}
		if v != vv {
			t.Errorf("Verifying %q: got %d, want %d", valueName, v, vv)
		}
	case []string:
		vv, _, err := key.GetStringsValue(valueName)
		if err != nil {
			t.Fatalf("Verifying %q: GetStringsValue: %v", valueName, err)
		}
		if !slices.Equal(v, vv) {
			t.Errorf("Verifying %q: got %v, want %v", valueName, v, vv)
		}
	case string:
		vv, vt, err := key.GetStringValue(valueName)
		if err != nil {
			t.Fatalf("GetStringValue(%q): %v", valueName, err)
		}
		if vt != registry.SZ {
			t.Fatalf("GetStringValue(%q) type: got 0x%08X, want 0x%08X", valueName, vt, registry.SZ)
		}
		if v != vv {
			t.Errorf("Verifying %q: got %q, want %q", valueName, v, vv)
		}
	case ExpandString:
		ev, err := registry.ExpandString(string(v))
		if err != nil {
			t.Fatalf("ExpandString: %v", err)
		}
		vv, vt, err := key.GetStringValue(valueName)
		if err != nil {
			t.Fatalf("GetStringValue(%q): %v", valueName, err)
		}
		if vt != registry.EXPAND_SZ {
			t.Fatalf("GetStringValue(%q) type: got 0x%08X, want 0x%08X", valueName, vt, registry.EXPAND_SZ)
		}
		evv, err := registry.ExpandString(vv)
		if err != nil {
			t.Fatalf("ExpandString: %v", err)
		}
		if ev != evv {
			t.Errorf("Verifying %q: got %q, want %q", valueName, ev, evv)
		}
	case []byte:
		vv, _, err := key.GetBinaryValue(valueName)
		if err != nil {
			t.Fatalf("Verifying %q: GetBinaryValue: %v", valueName, err)
		}
		if !slices.Equal(v, vv) {
			t.Errorf("Verifying %q: got %v, want %v", valueName, v, vv)
		}
	default:
		panic("unknown value type")
	}
}
