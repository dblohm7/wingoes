// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package pe

import (
	dpe "debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TODO(aaron): separate into cross-platform and windows-specific bits
// We'll need a sample PE binary to test with on non-Windows

func TestPE(t *testing.T) {
	// NOTE: file names should always match a module already loaded in our process.
	// kernel32 is always implicitly loaded
	files := []string{`C:\Windows\System32\kernel32.dll`, os.Args[0]}

	for _, file := range files {
		base := filepath.Base(file)
		t.Run(fmt.Sprintf("File_%s", base), func(t *testing.T) { testFile(t, file) })
		t.Run(fmt.Sprintf("FileVsModule_%s", base), func(t *testing.T) { testFileVsModule(t, file) })
		t.Run(fmt.Sprintf("VersionInfo_%s", base), func(t *testing.T) { testVersionInfo(t, file) })
	}
}

func testFile(t *testing.T, fname string) {
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

	var cv *IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED
	for _, de := range dbgDir {
		t.Logf("Type: %d", de.Type)
		if de.Type == IMAGE_DEBUG_TYPE_CODEVIEW {
			cv, err = pei.ExtractCodeViewInfo(de)
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

	t.Run("SystemAuthenticode", func(t *testing.T) { testAuthenticodeAgainstSystemAPI(t, fname, certs) })

	if cv != nil {
		t.Run("SystemDebugInfo", func(t *testing.T) { testDebugInfoAgainstSystemAPI(t, fname, cv) })
	}
}
