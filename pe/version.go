// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package pe

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	errFixedFileInfoTooShort = errors.New("buffer smaller than VS_FIXEDFILEINFO")
	errFixedFileInfoBadSig   = errors.New("bad VS_FIXEDFILEINFO signature")
)

type VersionNumber struct {
	Major uint16
	Minor uint16
	Patch uint16
	Build uint16
}

func (vn *VersionNumber) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", vn.Major, vn.Minor, vn.Patch, vn.Build)
}

type langAndCodePage struct {
	language uint16
	codePage uint16
}

type VersionInfo struct {
	buf            []byte
	translationIDs []langAndCodePage
	fixed          *windows.VS_FIXEDFILEINFO
}

const (
	enUS        = 0x0409
	langNeutral = 0
)

func NewVersionInfo(filepath string) (*VersionInfo, error) {
	bufSize, err := windows.GetFileVersionInfoSize(filepath, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_RESOURCE_TYPE_NOT_FOUND) {
			err = ErrNotPresent
		}
		return nil, err
	}

	buf := make([]byte, bufSize)
	if err := windows.GetFileVersionInfo(filepath, 0, bufSize, unsafe.Pointer(&buf[0])); err != nil {
		return nil, err
	}

	var fixed *windows.VS_FIXEDFILEINFO
	var fixedLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &fixedLen); err != nil {
		return nil, err
	}
	if fixedLen < uint32(unsafe.Sizeof(windows.VS_FIXEDFILEINFO{})) {
		return nil, errFixedFileInfoTooShort
	}
	if fixed.Signature != 0xFEEF04BD {
		return nil, errFixedFileInfoBadSig
	}

	// Preferred translations, in order of preference. No preference for code page.
	translationIDs := []langAndCodePage{
		langAndCodePage{
			language: enUS,
		},
		langAndCodePage{
			language: langNeutral,
		},
	}

	var ids *langAndCodePage
	var idsNumBytes uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&ids), &idsNumBytes); err == nil {
		idsSlice := unsafe.Slice(ids, idsNumBytes/uint32(unsafe.Sizeof(*ids)))
		translationIDs = append(translationIDs, idsSlice...)
	}

	return &VersionInfo{
		buf:            buf,
		translationIDs: translationIDs,
		fixed:          fixed,
	}, nil
}

func (vi *VersionInfo) VersionNumber() VersionNumber {
	f := vi.fixed

	return VersionNumber{
		Major: uint16(f.FileVersionMS >> 16),
		Minor: uint16(f.FileVersionMS & 0xFFFF),
		Patch: uint16(f.FileVersionLS >> 16),
		Build: uint16(f.FileVersionLS & 0xFFFF),
	}
}

func (vi *VersionInfo) queryWithLangAndCodePage(key string, lcp langAndCodePage) (string, error) {
	fq := fmt.Sprintf("\\StringFileInfo\\%04x%04x\\%s", lcp.language, lcp.codePage, key)

	var value *uint16
	var valueLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&vi.buf[0]), fq, unsafe.Pointer(&value), &valueLen); err != nil {
		return "", err
	}

	return windows.UTF16ToString(unsafe.Slice(value, valueLen)), nil
}

func (vi *VersionInfo) field(key string) (string, error) {
	for _, lcp := range vi.translationIDs {
		value, err := vi.queryWithLangAndCodePage(key, lcp)
		if err == nil {
			return value, nil
		}
		if !errors.Is(err, windows.ERROR_RESOURCE_TYPE_NOT_FOUND) {
			return "", err
		}
		// Otherwise we continue looping and try the next language
	}

	return "", ErrNotPresent
}

func (vi *VersionInfo) CompanyName() (string, error) {
	return vi.field("CompanyName")
}
