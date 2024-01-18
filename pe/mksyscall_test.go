// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package pe

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows_test.go mksyscall_test.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows_test.go

import (
	"github.com/dblohm7/wingoes"
	"golang.org/x/sys/windows"
)

const (
	// This constant is only valid when used with imagehlp
	_CERT_SECTION_TYPE_ANY WIN_CERT_TYPE = 0x00FF
)

type _SYMSRV_INDEX_INFO struct {
	SizeOfStruct uint32
	File         [windows.MAX_PATH + 1]uint16
	Stripped     int32 // Win32 BOOL
	Timestamp    uint32
	Size         uint32
	DBGFile      [windows.MAX_PATH + 1]uint16
	PDBFile      [windows.MAX_PATH + 1]uint16
	GUID         wingoes.GUID
	Sig          uint32
	Age          uint32
}

// _IMAGE_NT_HEADERS_FIXED is IMAGE_NT_HEADERS sans OptionalHeader, whose
// layout differs between 32 and 64 bit implementations.
type _IMAGE_NT_HEADERS_FIXED struct {
	Signature  uint32
	FileHeader FileHeader
}

//sys imageDirectoryEntryToDataEx(base uintptr, mappedAsImage byte, directoryEntry uint16, size *uint32, foundHeader *SectionHeader) (ret uintptr, err error) [failretval==0] = dbghelp.ImageDirectoryEntryToDataEx
//sys imageEnumerateCertificates(fileHandle windows.Handle, typeFilter WIN_CERT_TYPE, certificateCount *uint32, indices *uint32, indexCount uint32) (err error) [int32(failretval)==0] = imagehlp.ImageEnumerateCertificates
//sys imageGetCertificateData(fileHandle windows.Handle, certificateIndex uint32, certificate *byte, requiredLength *uint32) (err error) [int32(failretval)==0] = imagehlp.ImageGetCertificateData
//sys imageNtHeader(base uintptr) (ret *_IMAGE_NT_HEADERS_FIXED, err error) [failretval==nil] = dbghelp.ImageNtHeader
// TODO(aaron): Maybe use to test resolveRVA?
// imageSectionHeader(ntHeaders *_IMAGE_NT_HEADERS_FIXED, base uintptr, rva uint32) (ret *SectionHeader, err error) [failretval==nil] = dbghelp.ImageRvaToSection
//sys symSrvGetFileIndexInfoW(file *uint16, info *_SYMSRV_INDEX_INFO, flags uint32) (err error) [int32(failretval)==0] = dbghelp.SymSrvGetFileIndexInfoW?
