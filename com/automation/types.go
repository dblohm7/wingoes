// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package automation

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type BSTR uintptr

func NewBSTR(s string) BSTR {
	buf, err := windows.UTF16FromString(s)
	if err != nil {
		return 0
	}
	return NewBSTRFromUTF16(buf)
}

func NewBSTRFromUTF16(us []uint16) BSTR {
	return sysAllocStringLen(&us[0], uint32(len(us)))
}

func NewBSTRFromUTF16Ptr(up *uint16) BSTR {
	return sysAllocString(up)
}

func (bs *BSTR) Len() uint32 {
	return sysStringLen(*bs)
}

func (bs *BSTR) String() string {
	return windows.UTF16ToString(bs.toUTF16())
}

// toUTF16 is unsafe for general use because it returns a pointer that is
// not managed by the Go GC.
func (bs *BSTR) toUTF16() []uint16 {
	return unsafe.Slice(bs.toUTF16Ptr(), bs.Len())
}

func (bs *BSTR) ToUTF16() []uint16 {
	return append([]uint16{}, bs.toUTF16()...)
}

// toUTF16Ptr is unsafe for general use because it returns a pointer that is
// not managed by the Go GC.
func (bs *BSTR) toUTF16Ptr() *uint16 {
	return (*uint16)(unsafe.Pointer(*bs))
}

func (bs *BSTR) ToUTF16Ptr() *uint16 {
	slc := bs.ToUTF16()
	return &slc[0]
}

func (bs *BSTR) Clone() BSTR {
	return sysAllocStringLen(bs.toUTF16Ptr(), bs.Len())
}

func (bs *BSTR) IsNil() bool {
	return *bs == 0
}

func (bs *BSTR) Close() error {
	sysFreeString(*bs)
	*bs = 0
	return nil
}
