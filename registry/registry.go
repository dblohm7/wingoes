// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

// Package registry implements additional registry access bindings beyond the
// set included in x/sys/windows.
package registry

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/dblohm7/wingoes"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// DeleteSingleRegistryValue deletes the registry value named valueName
// within the subkey resolved by key and subKey. subKey may be empty.
// valueName may be empty, indicating that the default value should be deleted.
//
// DeleteSingleRegistryValue only deletes the value; the enclosing subkey will
// not be touched, even if it becomes empty as a result of the value deletion.
//
// If you need to specify any WOW64 flags, use the [registry] package instead.
func DeleteSingleRegistryValue(key registry.Key, subKey, valueName string) (err error) {
	var subKey16 *uint16
	if subKey != "" {
		subKey16, err = windows.UTF16PtrFromString(subKey)
		if err != nil {
			return err
		}
	}

	var valueName16 *uint16
	if valueName != "" {
		valueName16, err = windows.UTF16PtrFromString(valueName)
		if err != nil {
			return err
		}
	}

	return regDeleteKeyValue(key, subKey16, valueName16)
}

// RegGetSingleValueType is the type constraint for registry values supported by
// GetSingleRegistryValue.
type RegGetSingleValueType interface {
	uint32 | uint64 | string | []string | []byte
}

// ExpandString is a string containing references to environment variables.
// When retrieved from the registry as a normal string, any such variables
// are automatically expanded by the OS.
type ExpandString string

// RegSingleValueType is the type constraint for registry values supported by
// SetSingleRegistryValue.
type RegSetSingleValueType interface {
	RegGetSingleValueType | ExpandString
}

// Constants used by regGetValue to specify the desired data type of the
// requested registry value.
const (
	wantSZ       = 0x00000002
	wantExpandSZ = 0x00000004
	wantBinary   = 0x00000008
	wantDWORD    = 0x00000010
	wantMultiSZ  = 0x00000020
	wantQWORD    = 0x00000040
)

func getSingleRegistryValueFixedLen[T interface{ uint32 | uint64 }](key registry.Key, subKey16 *uint16, valueName16 *uint16, ptr *T) (err error) {
	data := unsafe.Pointer(ptr)
	var wantedDataType, actualDataType uint32
	var numBytes uint32

	switch p := any(ptr).(type) {
	case *uint32:
		wantedDataType = wantDWORD
		numBytes = uint32(unsafe.Sizeof(*p))
	case *uint64:
		// We allow both types in this case; DWORDs will fill the lower half
		wantedDataType = wantDWORD | wantQWORD
		numBytes = uint32(unsafe.Sizeof(*p))
	default:
		return os.ErrInvalid
	}

	if err := regGetValue(key, subKey16, valueName16, wantedDataType, &actualDataType, data, &numBytes); err != nil {
		if err == windows.ERROR_UNSUPPORTED_TYPE {
			return fmt.Errorf("%w: actual type is %s", err, regTypeStr(actualDataType))
		}
		return err
	}
	return nil
}

func getSingleRegistryValueVariableLen[T interface{ byte | uint16 }](key registry.Key, subKey16 *uint16, valueName16 *uint16, wantedDataType uint32) ([]T, error) {
	var actualDataType uint32
	var numBytes uint32

	if err := regGetValue(key, subKey16, valueName16, wantedDataType, &actualDataType, unsafe.Pointer(nil), &numBytes); err != nil {
		if err == windows.ERROR_UNSUPPORTED_TYPE {
			return nil, fmt.Errorf("%w: actual type is %s", err, regTypeStr(actualDataType))
		}
		return nil, err
	}
	if numBytes == 0 {
		return nil, nil
	}

	buf := make([]T, numBytes/uint32(unsafe.Sizeof(T(0))))
	if err := regGetValue(key, subKey16, valueName16, wantedDataType, &actualDataType, unsafe.Pointer(unsafe.SliceData(buf)), &numBytes); err != nil {
		return nil, err
	}

	// numBytes can be smaller than the original value returned during the query
	// for buffer length, so truncate if necessary.
	return buf[:numBytes/uint32(unsafe.Sizeof(T(0)))], nil
}

// GetSingleRegistryValue obtains the value named valueName of type T from the
// location specified by key and subKey. subKey may be empty. valueName may
// be empty, indicating that the value to be obtained is the default value.
//
// If you need to read multiple values from the same registry key, or specify
// WOW64 flags, use the [registry] package instead.
//
// When T is string, GetSingleRegistryValue returns values from both
// [registry.SZ] and [registry.EXPAND_SZ] value types. In the latter case, any
// environment variables in the value are expanded before being returned.
//
// When T is a uint64, GetSingleRegistryValue returns values from both
// [registry.DWORD] and [registry.QWORD] value types, with DWORDs returned
// as the lower 32 bits of the result.
func GetSingleRegistryValue[T RegGetSingleValueType](key registry.Key, subKey, valueName string) (result T, err error) {
	var zero T

	var subKey16 *uint16
	if subKey != "" {
		subKey16, err = windows.UTF16PtrFromString(subKey)
		if err != nil {
			return zero, err
		}
	}

	var valueName16 *uint16
	if valueName != "" {
		valueName16, err = windows.UTF16PtrFromString(valueName)
		if err != nil {
			return zero, err
		}
	}

	switch v := any(&result).(type) {
	case *uint32:
		if err := getSingleRegistryValueFixedLen(key, subKey16, valueName16, v); err != nil {
			return zero, err
		}
	case *uint64:
		if err := getSingleRegistryValueFixedLen(key, subKey16, valueName16, v); err != nil {
			return zero, err
		}
	case *string:
		buf, err := getSingleRegistryValueVariableLen[uint16](key, subKey16, valueName16, wantExpandSZ|wantSZ)
		if err != nil {
			return zero, err
		}
		if l := len(buf); l > 0 {
			*v = windows.UTF16ToString(buf[:l-1])
		}
	case *[]string:
		buf, err := getSingleRegistryValueVariableLen[uint16](key, subKey16, valueName16, wantMultiSZ)
		if err != nil {
			return zero, err
		}
		*v = wingoes.MultiSZDecode(buf)
	case *[]byte:
		*v, err = getSingleRegistryValueVariableLen[byte](key, subKey16, valueName16, wantBinary)
		if err != nil {
			return zero, err
		}
	default:
		return zero, os.ErrInvalid
	}

	return result, nil
}

// SetSingleRegistryValue sets the value named valueName of type T at the
// location specified by key and subKey. valueName may be empty, indicating
// that the value to be obtained is the default value.
//
// If you need to write multiple values to the same registry key, or specify
// WOW64 flags, use the [registry] package instead.
//
// When T is string, SetSingleRegistryValue always sets the value's type as
// [registry.SZ]. Use [ExpandString] as T to set a [registry.EXPAND_SZ] value.
//
// If the destination subkey does not yet exist, it will be automatically
// created as a non-volatile subkey with a default security descriptor.
func SetSingleRegistryValue[T RegSetSingleValueType](key registry.Key, subKey, valueName string, value T) (err error) {
	var subKey16 *uint16
	if subKey != "" {
		subKey16, err = windows.UTF16PtrFromString(subKey)
		if err != nil {
			return err
		}
	}

	var valueName16 *uint16
	if valueName != "" {
		valueName16, err = windows.UTF16PtrFromString(valueName)
		if err != nil {
			return err
		}
	}

	var data unsafe.Pointer
	var dataType uint32
	var numBytes uint32

	switch v := any(value).(type) {
	case uint32:
		data = unsafe.Pointer(&v)
		dataType = registry.DWORD
		numBytes = uint32(unsafe.Sizeof(v))
	case uint64:
		data = unsafe.Pointer(&v)
		dataType = registry.QWORD
		numBytes = uint32(unsafe.Sizeof(v))
	case ExpandString:
		str16, err := windows.UTF16FromString(string(v))
		if err != nil {
			return err
		}
		data = unsafe.Pointer(unsafe.SliceData(str16))
		dataType = registry.EXPAND_SZ
		numBytes = uint32(len(str16) * int(unsafe.Sizeof(uint16(0))))
	case string:
		str16, err := windows.UTF16FromString(v)
		if err != nil {
			return err
		}
		data = unsafe.Pointer(unsafe.SliceData(str16))
		dataType = registry.SZ
		numBytes = uint32(len(str16) * int(unsafe.Sizeof(uint16(0))))
	case []string:
		slc, err := wingoes.MultiSZEncode(v)
		if err != nil {
			return err
		}
		data = unsafe.Pointer(unsafe.SliceData(slc))
		dataType = registry.MULTI_SZ
		numBytes = uint32(len(slc) * int(unsafe.Sizeof(uint16(0))))
	case []byte:
		data = unsafe.Pointer(unsafe.SliceData(v))
		dataType = registry.BINARY
		numBytes = uint32(len(v))
	default:
		return os.ErrInvalid
	}

	return regSetKeyValue(key, subKey16, valueName16, dataType, data, numBytes)
}

func regTypeStr(dataType uint32) string {
	switch dataType {
	case registry.SZ:
		return "string"
	case registry.EXPAND_SZ:
		return "ExpandString"
	case registry.BINARY:
		return "[]byte"
	case registry.DWORD:
		return "uint32"
	case registry.MULTI_SZ:
		return "[]string"
	case registry.QWORD:
		return "uint64"
	default:
		return fmt.Sprintf("<type 0x%08X>", dataType)
	}
}
