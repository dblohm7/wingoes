// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package pe

import (
	"bytes"
	dpe "debug/pe"
	"os"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TODO(aaron): separate into cross-platform and windows-specific bits

func getTestBinaryFileName() string {
	// TODO(aaron): Test against both!
	// NOTE: return value should match a module already loaded in our process
	if runtime.GOOS == "windows" {
		// kernel32 is always implicitly loaded
		return `C:\Windows\System32\kernel32.dll`
	} else {
		// Use ourselves!
		return os.Args[0]
	}
}

func TestFile(t *testing.T) {
	fname := getTestBinaryFileName()

	pei, err := NewPEFromFileName(fname)
	if err != nil {
		t.Fatalf("NewPEFromFile: %v", err)
	}
	defer pei.Close()

	t.Logf("Limit: 0x%08X (%d)\n", pei.r.Limit(), pei.r.Limit())

	dd := pei.optionalHeader.GetDataDirectory()
	for i, e := range dd {
		t.Logf("%02d: V: 0x%08X, FOff: 0x%08X", i, e.VirtualAddress, resolveRVA(pei, e.VirtualAddress))
	}

	t.Logf("\n")

	for i, s := range pei.sections {
		t.Logf("%02d: %q F: 0x%08X, FS: 0x%08X, V: 0x%08X, VS: 0x%08X", i, s.NameString(), s.PointerToRawData, s.SizeOfRawData, s.VirtualAddress, s.VirtualSize)
	}

	dbgDirAny, err := pei.DataDirectoryEntry(dpe.IMAGE_DIRECTORY_ENTRY_DEBUG)
	if err != nil && err != ErrNotPresent {
		t.Fatalf("(*PEInfo).DataDirectoryEntry(%d) error %v", dpe.IMAGE_DIRECTORY_ENTRY_DEBUG, err)
	}

	dbgDir, ok := dbgDirAny.([]IMAGE_DEBUG_DIRECTORY)
	if dbgDirAny != nil && !ok {
		t.Errorf("did not get []IMAGE_DEBUG_DIRECTORY")
	}

	t.Logf("\n")
	if len(dbgDir) == 0 {
		t.Logf("No debug directory entries")
	} else {
		t.Logf("Debug Info:")
	}

	for _, de := range dbgDir {
		t.Logf("Type: %d", de.Type)
		if de.Type == IMAGE_DEBUG_TYPE_CODEVIEW {
			cv, err := pei.ExtractCodeViewInfo(de)
			if err != nil {
				t.Errorf("ExtractCodeViewInfo: %v", err)
				continue
			}
			t.Logf("CodeView %q: %q", cv.String(), cv.PDBPath)
			break
		}
	}

	t.Logf("\n")
	certsAny, err := pei.DataDirectoryEntry(dpe.IMAGE_DIRECTORY_ENTRY_SECURITY)
	if err != nil && err != ErrNotPresent {
		t.Fatalf("(*PEInfo).DataDirectoryEntry(%d) error %v", dpe.IMAGE_DIRECTORY_ENTRY_SECURITY, err)
	}

	certs, ok := certsAny.([]AuthenticodeCert)
	if certsAny != nil && !ok {
		t.Errorf("did not get []AuthenticodeCert")
	}

	t.Logf("%d certs embedded in binary", len(certs))
	for i, cert := range certs {
		t.Logf("%02d: Rev 0x%04X, Type %d, %d bytes", i, cert.Revision(), cert.Type(), len(cert.Data()))
	}

	// TODO(aaron): Compare authenticode info against ImageGetCertificateData
	// TODO(aaron): Compare debug info against SymSrvGetFileIndexInfoW
}

func TestFileVsModule(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("This test depends on the Windows dynamic linker")
	}

	fname := getTestBinaryFileName()

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

func TestVersionInfo(t *testing.T) {
	fname := getTestBinaryFileName()

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
