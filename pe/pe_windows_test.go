// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package pe

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func testAuthenticodeAgainstSystemAPI(t *testing.T, filename string, certs []AuthenticodeCert) {
	syscerts, err := getCertDataViaSystem(filename)
	if err != nil {
		t.Fatalf("getCertDataViaSystem(%q) error %v", filename, err)
	}

	if len(certs) != len(syscerts) {
		t.Errorf("len mismatch")
	}

	var testCerts [2]*AuthenticodeCert
	for i, slc := range [][]AuthenticodeCert{certs, syscerts} {
		for j, cert := range slc {
			if cert.Revision() != WIN_CERT_REVISION_2_0 || cert.Type() != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
				continue
			}
			testCerts[i] = &slc[j]
			break
		}
	}

	if !reflect.DeepEqual(testCerts[0], testCerts[1]) {
		t.Errorf("DeepEqual failed")
	}
}

func testDebugInfoAgainstSystemAPI(t *testing.T, filename string, cv *IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED) {
	syscv, err := getCodeViewInfoViaSystem(filename)
	if err != nil {
		var dllerr *windows.DLLError
		if errors.As(err, &dllerr) {
			t.Skipf("Test requires dbghelp.dll version 6.6 or later")
		}
		t.Fatalf("getCodeViewInfoViaSystem(%q) error %v", filename, err)
	}

	if !reflect.DeepEqual(cv, syscv) {
		t.Errorf("DeepEqual failed")
	}
}

func getCodeViewInfoViaSystem(filename string) (result *IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED, err error) {
	filename16, err := windows.UTF16PtrFromString(filename)
	if err != nil {
		return nil, err
	}

	info := _SYMSRV_INDEX_INFO{
		SizeOfStruct: uint32(unsafe.Sizeof(_SYMSRV_INDEX_INFO{})),
	}
	if err := symSrvGetFileIndexInfo(filename16, &info, 0); err != nil {
		return nil, err
	}

	result = &IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED{
		GUID:    info.GUID,
		Age:     info.Age,
		PDBPath: windows.UTF16ToString(info.PDBFile[:]),
	}
	return result, nil
}

func getCertDataViaSystem(filename string) (result []AuthenticodeCert, err error) {
	h, err := windows.Open(filename, windows.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	var certCount uint32
	if err := imageEnumerateCertificates(h, _CERT_SECTION_TYPE_ANY, &certCount, nil, 0); err != nil {
		return nil, err
	}
	if certCount == 0 {
		return nil, nil
	}

	result = make([]AuthenticodeCert, 0, certCount)
	for i := uint32(0); i < certCount; i++ {
		reqd := uint32(0)
		if err := imageGetCertificateData(h, i, nil, &reqd); err != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}

		buf := make([]byte, reqd)
		if err := imageGetCertificateData(h, i, unsafe.SliceData(buf), &reqd); err != nil {
			return nil, err
		}
		r := bytes.NewReader(buf)

		var entry AuthenticodeCert
		if err := binaryRead(r, &entry.header); err != nil {
			return nil, err
		}

		entry.data = buf[unsafe.Sizeof(_WIN_CERTIFICATE_HEADER{}):]
		result = append(result, entry)
	}

	return result, nil
}

func testFileVsModule(t *testing.T, fname string) {
	pef, err := NewPEFromFileName(fname)
	if err != nil {
		t.Errorf("NewPEFromFile: %v", err)
	}
	defer pef.Close()

	fname16, err := windows.UTF16PtrFromString(fname)
	if err != nil {
		t.Fatalf("converting %q to UTF-16: %v", fname, err)
	}

	var hmod windows.Handle
	if err := windows.GetModuleHandleEx(
		windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		fname16,
		&hmod,
	); err != nil {
		t.Fatalf("loading %q: %v", fname, err)
	}

	pem, err := NewPEFromHMODULE(hmod)
	if err != nil {
		t.Errorf("NewPEFromHMODULE: %v", err)
	}
	defer pem.Close()

	if !reflect.DeepEqual(pef.fileHeader, pem.fileHeader) {
		t.Errorf("DeepEqual failed on fileHeader")
	}

	// The optional header's DataDirectory will be modified by loader relocations,
	// so we need to exclude that from the comparison.
	pefOH := pef.optionalHeader.(*optionalHeaderForGOARCH)
	pefOHBytes := unsafe.Slice((*byte)(unsafe.Pointer(pefOH)), unsafe.Sizeof(*pefOH)-unsafe.Sizeof(pefOH.DataDirectory))
	// ImageBase is pretty much guaranteed to differ, so make a copy and set that the module's value to the file's value.
	pemOH := pem.optionalHeader.(*optionalHeaderForGOARCH)
	pemOHCopy := *pemOH
	pemOHCopy.ImageBase = pefOH.ImageBase

	pemOHBytes := unsafe.Slice((*byte)(unsafe.Pointer(&pemOHCopy)), unsafe.Sizeof(pemOHCopy)-unsafe.Sizeof(pemOHCopy.DataDirectory))

	if !bytes.Equal(pefOHBytes, pemOHBytes) {
		t.Errorf("bytes.Equal failed on optionalHeader:\n\n%#v\n\nvs\n\n%#v\n\n", pefOHBytes, pemOHBytes)
	}

	// TODO(aaron): flesh out this test as (*PEInfo).DataDirectoryEntry is fleshed out
	// Compare some DataDirectory stuff between file and module. Note that
	// IMAGE_DIRECTORY_ENTRY_SECURITY is unavailable in modules.
	ddIdx := IMAGE_DIRECTORY_ENTRY_DEBUG
	dbgInfoFileAny, err := pef.DataDirectoryEntry(ddIdx)
	if err != nil {
		if err != ErrNotPresent {
			t.Errorf("obtaining DataDirectory[%d] from file: %v", ddIdx, err)
		}
	}

	dbgInfoModuleAny, err := pem.DataDirectoryEntry(ddIdx)
	if err != nil {
		if err != ErrNotPresent {
			t.Errorf("obtaining DataDirectory[%d] from module: %v", ddIdx, err)
		}
	}

	if (dbgInfoFileAny == nil || dbgInfoModuleAny == nil) && dbgInfoFileAny != dbgInfoModuleAny {
		t.Errorf("DataDirectoryEntry[%d] for file returned %v while module returned %v", ddIdx, dbgInfoFileAny, dbgInfoModuleAny)
	}

	if dbgInfoFileAny != nil && dbgInfoModuleAny != nil {
		dbgInfoFile, ok := dbgInfoFileAny.([]IMAGE_DEBUG_DIRECTORY)
		if !ok {
			t.Errorf("type assertion failed for dbgInfoFileAny")
		}

		dbgInfoModule, ok := dbgInfoModuleAny.([]IMAGE_DEBUG_DIRECTORY)
		if !ok {
			t.Errorf("type assertion failed for dbgInfoFileModule")
		}

		if len(dbgInfoFile) != len(dbgInfoModule) {
			t.Errorf("length mismatch between dbgInfoFile (%d) and dbgInfoModule (%d)", len(dbgInfoFile), len(dbgInfoModule))
		} else {
			for i, def := range dbgInfoFile {
				dem := dbgInfoModule[i]
				if def.Type != dem.Type {
					t.Errorf("type mismatch between dbgInfoFile[%d] (%d) and dbgInfoModule[%d] (%d)", i, def.Type, i, dem.Type)
					continue
				}
				if def.Type == IMAGE_DEBUG_TYPE_CODEVIEW {
					cvf, err := pef.ExtractCodeViewInfo(def)
					if err != nil {
						t.Errorf("failed extracting CodeView info from dbgInfoFile[%d]: %v", i, err)
						continue
					}

					cvm, err := pem.ExtractCodeViewInfo(dem)
					if err != nil {
						t.Errorf("failed extracting CodeView info from dbgInfoModule[%d]: %v", i, err)
						continue
					}

					if !reflect.DeepEqual(*cvf, *cvm) {
						t.Errorf("debug info mismatch")
					}
				}
			}
		}
	}
}

func testVersionInfo(t *testing.T, fname string) {
	vi, err := NewVersionInfo(fname)
	if err != nil {
		if err == ErrNotPresent {
			t.Skipf("No version info present in %q", fname)
		} else {
			t.Fatalf("NewVersionInfo failed: %v", err)
		}
	}

	verNum := vi.VersionNumber()
	t.Logf("Version number: %q", verNum.String())

	companyName, err := vi.Field("CompanyName")
	if err != nil {
		t.Errorf("CompanyName failed: %v", err)
	} else {
		t.Logf("CompanyName: %q", companyName)
	}
}

func TestModuleVsSystem(t *testing.T) {
	k32 := windows.MustLoadDLL("kernel32.dll")
	pem, err := NewPEFromDLL(k32)
	if err != nil {
		t.Errorf("NewPEFromHMODULE error: %v", err)
	}
	defer pem.Close()

	fh, err := getFileHeaderViaSystem(uintptr(k32.Handle))
	if err != nil {
		t.Fatalf("getFileHeaderViaSystem error: %v", err)
	}

	if uintptr(unsafe.Pointer(fh)) != uintptr(unsafe.Pointer(pem.fileHeader)) {
		t.Errorf("FileHeader pointers do not match")
	}

	var ddeZero DataDirectoryEntry
	dd := pem.optionalHeader.GetDataDirectory()
	for i, dde := range dd {
		ddeSys, err := getDataDirectoryEntryViaSystem(uintptr(k32.Handle), DataDirectoryIndex(i))
		if err != nil {
			if dde == ddeZero {
				// Not present; not an error
				continue
			}
			t.Fatalf("getDataDirectoryEntryViaSystem error: %v", err)
		}

		if !reflect.DeepEqual(dde, *ddeSys) {
			t.Errorf("DeepEqual failed on DataDirectory[%d]", i)
		}
	}
}

func getFileHeaderViaSystem(hmodule uintptr) (*FileHeader, error) {
	ntFixed, err := imageNtHeader(hmodule)
	if err != nil {
		return nil, err
	}

	return &ntFixed.FileHeader, nil
}

func getDataDirectoryEntryViaSystem(hmodule uintptr, ddIndex DataDirectoryIndex) (dde *DataDirectoryEntry, err error) {
	var size uint32
	address, err := imageDirectoryEntryToDataEx(hmodule, 1, uint16(ddIndex), &size, nil)
	if err != nil {
		return nil, err
	}

	return &DataDirectoryEntry{
		VirtualAddress: uint32(address - hmodule),
		Size:           size,
	}, nil
}
