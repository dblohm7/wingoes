// Copyright (c) 2023 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package com

import (
	"io"
	"math"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/dblohm7/wingoes"
	"github.com/dblohm7/wingoes/internal"
	"golang.org/x/sys/windows"
)

var (
	IID_ISequentialStream = &IID{0x0C733A30, 0x2A1C, 0x11CE, [8]byte{0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D}}
	IID_IStream           = &IID{0x0000000C, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
)

type STGC uint32

const (
	STGC_DEFAULT                            = STGC(0)
	STGC_OVERWRITE                          = STGC(1)
	STGC_ONLYIFCURRENT                      = STGC(2)
	STGC_DANGEROUSLYCOMMITMERELYTODISKCACHE = STGC(4)
	STGC_CONSOLIDATE                        = STGC(8)
)

type LOCKTYPE uint32

const (
	LOCK_WRITE     = LOCKTYPE(1)
	LOCK_EXCLUSIVE = LOCKTYPE(2)
	LOCK_ONLYONCE  = LOCKTYPE(4)
)

type STGTY uint32

const (
	STGTY_STORAGE   = STGTY(1)
	STGTY_STREAM    = STGTY(2)
	STGTY_LOCKBYTES = STGTY(3)
	STGTY_PROPERTY  = STGTY(4)
)

type STATFLAG uint32

const (
	STATFLAG_DEFAULT = STATFLAG(0)
	STATFLAG_NONAME  = STATFLAG(1)
	STATFLAG_NOOPEN  = STATFLAG(2)
)

type STATSTG struct {
	Name           COMAllocatedString
	Type           STGTY
	Size           uint64
	MTime          windows.Filetime
	CTime          windows.Filetime
	ATime          windows.Filetime
	Mode           uint32
	LocksSupported LOCKTYPE
	ClsID          CLSID
	_              uint32 // StateBits
	_              uint32 // reserved
}

type ISequentialStreamABI struct {
	IUnknownABI
}

type IStreamABI struct {
	ISequentialStreamABI
}

type Stream struct {
	GenericObject[IStreamABI]
}

const hrS_FALSE = wingoes.HRESULT(1)

func (abi *ISequentialStreamABI) Read(p []byte) (n int, err error) {
	var cbRead uint32
	method := unsafe.Slice(abi.Vtbl, 5)[3]

	rc, _, _ := syscall.SyscallN(
		method,
		uintptr(unsafe.Pointer(abi)),
		uintptr(unsafe.Pointer(&p[0])),
		uintptr(uint32(len(p))),
		uintptr(unsafe.Pointer(&cbRead)),
	)
	e := wingoes.ErrorFromHRESULT(wingoes.HRESULT(rc))
	if e.Failed() {
		return n, e
	}

	// Various implementations of IStream handle EOF differently. We need to
	// deal with both.
	if e.AsHRESULT() == hrS_FALSE || (len(p) > 0 && cbRead == 0) {
		return int(cbRead), io.EOF
	}

	return int(cbRead), nil
}

func (abi *ISequentialStreamABI) Write(p []byte) (int, error) {
	var cbWritten uint32
	method := unsafe.Slice(abi.Vtbl, 5)[4]

	rc, _, _ := syscall.SyscallN(
		method,
		uintptr(unsafe.Pointer(abi)),
		uintptr(unsafe.Pointer(&p[0])),
		uintptr(uint32(len(p))),
		uintptr(unsafe.Pointer(&cbWritten)),
	)
	if e := wingoes.ErrorFromHRESULT(wingoes.HRESULT(rc)); e.Failed() {
		return 0, e
	}

	return int(cbWritten), nil
}

func (abi *IStreamABI) Seek(offset int64, whence int) (n int64, _ error) {
	var hr wingoes.HRESULT
	method := unsafe.Slice(abi.Vtbl, 14)[5]

	if runtime.GOARCH == "386" {
		words := (*[2]uintptr)(unsafe.Pointer(&offset))
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			words[0],
			words[1],
			uintptr(uint32(whence)),
			uintptr(unsafe.Pointer(&n)),
		)
		hr = wingoes.HRESULT(rc)
	} else {
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			uintptr(offset),
			uintptr(uint32(whence)),
			uintptr(unsafe.Pointer(&n)),
		)
		hr = wingoes.HRESULT(rc)
	}

	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() {
		return 0, e
	}

	return n, nil
}

func (abi *IStreamABI) SetSize(newSize uint64) error {
	var hr wingoes.HRESULT
	method := unsafe.Slice(abi.Vtbl, 14)[6]

	if runtime.GOARCH == "386" {
		words := (*[2]uintptr)(unsafe.Pointer(&newSize))
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			words[0],
			words[1],
		)
		hr = wingoes.HRESULT(rc)
	} else {
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			uintptr(newSize),
		)
		hr = wingoes.HRESULT(rc)
	}

	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() {
		return e
	}

	return nil
}

func (abi *IStreamABI) CopyTo(dest *IStreamABI, numBytesToCopy uint64) (bytesRead, bytesWritten uint64, _ error) {
	var hr wingoes.HRESULT
	method := unsafe.Slice(abi.Vtbl, 14)[7]

	if runtime.GOARCH == "386" {
		words := (*[2]uintptr)(unsafe.Pointer(&numBytesToCopy))
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			uintptr(unsafe.Pointer(dest)),
			words[0],
			words[1],
			uintptr(unsafe.Pointer(&bytesRead)),
			uintptr(unsafe.Pointer(&bytesWritten)),
		)
		hr = wingoes.HRESULT(rc)
	} else {
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			uintptr(unsafe.Pointer(dest)),
			uintptr(numBytesToCopy),
			uintptr(unsafe.Pointer(&bytesRead)),
			uintptr(unsafe.Pointer(&bytesWritten)),
		)
		hr = wingoes.HRESULT(rc)
	}

	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() {
		return bytesRead, bytesWritten, e
	}

	return bytesRead, bytesWritten, nil
}

func (abi *IStreamABI) Commit(flags STGC) error {
	method := unsafe.Slice(abi.Vtbl, 14)[8]

	rc, _, _ := syscall.SyscallN(
		method,
		uintptr(unsafe.Pointer(abi)),
		uintptr(flags),
	)

	if e := wingoes.ErrorFromHRESULT(wingoes.HRESULT(rc)); e.Failed() {
		return e
	}

	return nil
}

func (abi *IStreamABI) Revert() error {
	method := unsafe.Slice(abi.Vtbl, 14)[9]

	rc, _, _ := syscall.SyscallN(
		method,
		uintptr(unsafe.Pointer(abi)),
	)

	if e := wingoes.ErrorFromHRESULT(wingoes.HRESULT(rc)); e.Failed() {
		return e
	}

	return nil
}

func (abi *IStreamABI) LockRegion(offset, numBytes uint64, lockType LOCKTYPE) error {
	var hr wingoes.HRESULT
	method := unsafe.Slice(abi.Vtbl, 14)[10]

	if runtime.GOARCH == "386" {
		oWords := (*[2]uintptr)(unsafe.Pointer(&offset))
		nWords := (*[2]uintptr)(unsafe.Pointer(&numBytes))
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			oWords[0],
			oWords[1],
			nWords[0],
			nWords[1],
			uintptr(lockType),
		)
		hr = wingoes.HRESULT(rc)
	} else {
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			uintptr(offset),
			uintptr(numBytes),
			uintptr(lockType),
		)
		hr = wingoes.HRESULT(rc)
	}

	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() {
		return e
	}

	return nil
}

func (abi *IStreamABI) UnlockRegion(offset, numBytes uint64, lockType LOCKTYPE) error {
	var hr wingoes.HRESULT
	method := unsafe.Slice(abi.Vtbl, 14)[11]

	if runtime.GOARCH == "386" {
		oWords := (*[2]uintptr)(unsafe.Pointer(&offset))
		nWords := (*[2]uintptr)(unsafe.Pointer(&numBytes))
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			oWords[0],
			oWords[1],
			nWords[0],
			nWords[1],
			uintptr(lockType),
		)
		hr = wingoes.HRESULT(rc)
	} else {
		rc, _, _ := syscall.SyscallN(
			method,
			uintptr(unsafe.Pointer(abi)),
			uintptr(offset),
			uintptr(numBytes),
			uintptr(lockType),
		)
		hr = wingoes.HRESULT(rc)
	}

	if e := wingoes.ErrorFromHRESULT(hr); e.Failed() {
		return e
	}

	return nil
}

func (st *STATSTG) Close() error {
	return st.Name.Close()
}

func (abi *IStreamABI) Stat(flags STATFLAG) (result STATSTG, _ error) {
	method := unsafe.Slice(abi.Vtbl, 14)[12]

	rc, _, _ := syscall.SyscallN(
		method,
		uintptr(unsafe.Pointer(abi)),
		uintptr(unsafe.Pointer(&result)),
		uintptr(flags),
	)

	if e := wingoes.ErrorFromHRESULT(wingoes.HRESULT(rc)); e.Failed() {
		return result, e
	}

	return result, nil
}

func (abi *IStreamABI) Clone() (result *IUnknownABI, _ error) {
	method := unsafe.Slice(abi.Vtbl, 14)[13]

	rc, _, _ := syscall.SyscallN(
		method,
		uintptr(unsafe.Pointer(abi)),
		uintptr(unsafe.Pointer(&result)),
	)

	if e := wingoes.ErrorFromHRESULT(wingoes.HRESULT(rc)); e.Failed() {
		return nil, e
	}

	return result, nil
}

func (o Stream) GetIID() *IID {
	return IID_IStream
}

func (o Stream) Make(r ABIReceiver) any {
	if r == nil {
		return Stream{}
	}

	runtime.SetFinalizer(r, ReleaseABI)

	pp := (**IStreamABI)(unsafe.Pointer(r))
	return Stream{GenericObject[IStreamABI]{Pp: pp}}
}

func (o Stream) UnsafeUnwrap() *IStreamABI {
	return *(o.Pp)
}

func (o Stream) Read(buf []byte) (int, error) {
	p := *(o.Pp)
	return p.Read(buf)
}

func (o Stream) Write(buf []byte) (int, error) {
	p := *(o.Pp)
	return p.Write(buf)
}

func (o Stream) Seek(offset int64, whence int) (n int64, _ error) {
	p := *(o.Pp)
	return p.Seek(offset, whence)
}

func (o Stream) SetSize(newSize uint64) error {
	p := *(o.Pp)
	return p.SetSize(newSize)
}

func (o Stream) CopyTo(dest Stream, numBytesToCopy uint64) (bytesRead, bytesWritten uint64, _ error) {
	p := *(o.Pp)
	return p.CopyTo(dest.UnsafeUnwrap(), numBytesToCopy)
}

func (o Stream) Commit(flags STGC) error {
	p := *(o.Pp)
	return p.Commit(flags)
}

func (o Stream) Revert() error {
	p := *(o.Pp)
	return p.Revert()
}

func (o Stream) LockRegion(offset, numBytes uint64, lockType LOCKTYPE) error {
	p := *(o.Pp)
	return p.LockRegion(offset, numBytes, lockType)
}

func (o Stream) UnlockRegion(offset, numBytes uint64, lockType LOCKTYPE) error {
	p := *(o.Pp)
	return p.UnlockRegion(offset, numBytes, lockType)
}

func (o Stream) Stat(flags STATFLAG) (result STATSTG, _ error) {
	p := *(o.Pp)
	return p.Stat(flags)
}

func (o Stream) Clone() (result Stream, _ error) {
	p := *(o.Pp)
	punk, err := p.Clone()
	if err != nil {
		return result, err
	}

	return result.Make(&punk).(Stream), nil
}

const hrE_OUTOFMEMORY = wingoes.HRESULT(-((0x8007000E ^ 0xFFFFFFFF) + 1))

// NewMemoryStream creates a new in-memory Stream object initially containing
// initialBytes. Its seek pointer is guaranteed to be the start of the stream.
func NewMemoryStream(initialBytes []byte) (result Stream, _ error) {
	if len(initialBytes) > math.MaxInt32 {
		return result, wingoes.ErrorFromHRESULT(hrE_OUTOFMEMORY)
	}

	// SHCreateMemStream is not safe to use until Windows 8.
	if !wingoes.IsWin8OrGreater() {
		return newMemoryStreamLegacy(initialBytes)
	}

	var base *byte
	var length uint32
	if l := len(initialBytes); l > 0 {
		base = &initialBytes[0]
		length = uint32(l)
	}

	punk := shCreateMemStream(base, length)
	if punk == nil {
		return result, wingoes.ErrorFromHRESULT(hrE_OUTOFMEMORY)
	}

	obj := result.Make(&punk).(Stream)
	_, err := obj.Seek(0, io.SeekStart)
	if err != nil {
		return result, err
	}

	return obj, err
}

func newMemoryStreamLegacy(initialBytes []byte) (result Stream, _ error) {
	ppstream := NewABIReceiver()
	hr := createStreamOnHGlobal(internal.HGLOBAL(0), true, ppstream)
	if err := wingoes.ErrorFromHRESULT(hr); hr.Failed() {
		return result, err
	}

	obj := result.Make(ppstream).(Stream)
	if len(initialBytes) == 0 {
		return obj, nil
	}

	err := obj.SetSize(uint64(len(initialBytes)))
	if err != nil {
		return result, err
	}

	n, err := obj.Write(initialBytes)
	if err != nil {
		return result, err
	}
	if n != len(initialBytes) {
		return result, io.ErrShortWrite
	}

	_, err = obj.Seek(0, io.SeekStart)
	if err != nil {
		return result, err
	}

	return obj, err
}
