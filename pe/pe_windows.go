// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package pe provides a robust parser for PE binaries.
package pe

import (
	"bufio"
	"bytes"
	dpe "debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"golang.org/x/exp/constraints"
	"golang.org/x/sys/windows"
)

// PEInfo represents the partially-parsed headers from a PE binary.
type PEInfo struct {
	r              peReader
	fileHeader     *dpe.FileHeader
	optionalHeader *optionalHeader
	sections       []peSectionHeader
}

const (
	offsetIMAGE_DOS_HEADERe_lfanew = 60
	sizeIMAGE_DOS_HEADER           = 64
	maxNumSections                 = 96 // per PE spec
)

var (
	ErrBadLength           = errors.New("effective length did not match expected length")
	ErrNotCodeView         = errors.New("debug info is not CodeView")
	ErrNotPresent          = errors.New("not present in this PE image")
	ErrIndexOutOfRange     = errors.New("index out of range")
	ErrInvalidBinary       = errors.New("invalid PE binary")
	ErrUnavailableInModule = errors.New("this information is unavailable from loaded modules; the PE file itself must be examined")
	ErrUnsupportedMachine  = errors.New("unsupported machine")
)

type pe struct {
	base           uintptr
	limit          uintptr
	fileHeader     *dpe.FileHeader
	optionalHeader *optionalHeader
}

type peFile struct {
	*os.File
	pe
}

func (pef *peFile) Base() uintptr {
	return pef.pe.base
}

func (pef *peFile) Limit() uintptr {
	if pef.limit == 0 {
		if fi, err := pef.Stat(); err == nil {
			pef.limit = uintptr(fi.Size())
		}
	}
	return pef.limit
}

type peModule struct {
	*bytes.Reader
	pe
}

func (pei *peModule) Base() uintptr {
	return pei.pe.base
}

func (pei *peModule) Close() error {
	return nil
}

func (pei *peModule) Limit() uintptr {
	if pei.limit == 0 {
		pei.limit = pei.base + uintptr(pei.Size())
	}
	return pei.limit
}

// NewPEFromBaseAddressAndSize parses the headers in a PE binary loaded
// into the current process's address space at address baseAddr with known
// size. If you do not have the size, use NewPEFromBaseAddress instead.
// Upon success it returns a non-nil *PEInfo, otherwise it returns a nil *PEInfo
// and a non-nil error.
// If the module is unloaded while the returned *PEInfo is still in use,
// its behaviour will become undefined.
func NewPEFromBaseAddressAndSize(baseAddr, size uintptr) (*PEInfo, error) {
	slc := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), size)
	r := bytes.NewReader(slc)
	peMod := &peModule{Reader: r, pe: pe{base: baseAddr, limit: baseAddr + size}}
	return loadHeaders(peMod)
}

// NewPEFromBaseAddress parses the headers in a PE binary loaded into the
// current process's address space at address baseAddr.
// Upon success it returns a non-nil *PEInfo, otherwise it returns a nil *PEInfo
// and a non-nil error.
// If the module is unloaded while the returned *PEInfo is still in use,
// its behaviour will become undefined.
func NewPEFromBaseAddress(baseAddr uintptr) (*PEInfo, error) {
	var modInfo windows.ModuleInfo
	if err := windows.GetModuleInformation(
		windows.CurrentProcess(),
		windows.Handle(baseAddr),
		&modInfo,
		uint32(unsafe.Sizeof(modInfo)),
	); err != nil {
		return nil, fmt.Errorf("querying module handle: %w", err)
	}

	return NewPEFromBaseAddressAndSize(baseAddr, uintptr(modInfo.SizeOfImage))
}

// NewPEFromHMODULE parses the headers in a PE binary identified by hmodule that
// is currently loaded into the current process's address space.
// Upon success it returns a non-nil *PEInfo, otherwise it returns a nil *PEInfo
// and a non-nil error.
// If the module is unloaded while the returned *PEInfo is still in use,
// its behaviour will become undefined.
func NewPEFromHMODULE(hmodule windows.Handle) (*PEInfo, error) {
	return NewPEFromBaseAddress(uintptr(hmodule) & ^uintptr(3))
}

// NewPEFromFileName opens a PE binary located at filename and parses its PE
// headers. Upon success it returns a non-nil *PEInfo, otherwise it returns a
// nil *PEInfo and a non-nil error.
// Call Close() on the returned *PEInfo when it is no longer needed.
func NewPEFromFileName(filename string) (*PEInfo, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return newPEFromFile(f)
}

func newPEFromFile(f *os.File) (*PEInfo, error) {
	pef := &peFile{File: f}
	return loadHeaders(pef)
}

// NewPEFromFileHandle parses the PE headers from hfile, an open Win32 file handle.
// It does *not* consume hfile.
// Upon success it returns a non-nil *PEInfo, otherwise it returns a
// nil *PEInfo and a non-nil error.
// Call Close() on the returned *PEInfo when it is no longer needed.
func NewPEFromFileHandle(hfile windows.Handle) (*PEInfo, error) {
	// Duplicate hfile so that we don't consume it.
	var hfileDup windows.Handle
	cp := windows.CurrentProcess()
	if err := windows.DuplicateHandle(
		cp,
		hfile,
		cp,
		&hfileDup,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return nil, err
	}

	return newPEFromFile(os.NewFile(uintptr(hfileDup), "PEFromFileHandle"))
}

type peReader interface {
	Base() uintptr
	io.Closer
	io.ReaderAt
	io.ReadSeeker
	Limit() uintptr
}

func addOffset[O constraints.Integer](base uintptr, off O) uintptr {
	if off >= 0 {
		return base + uintptr(off)
	}

	negation := uintptr(-off)
	if negation >= base {
		return 0
	}
	return base - negation
}

func readStruct[T any, O constraints.Integer](r peReader, rva O) (*T, error) {
	szT := unsafe.Sizeof(*((*T)(nil)))
	switch v := r.(type) {
	case *peFile:
		buf := make([]byte, szT)
		n, err := r.ReadAt(buf, int64(rva))
		if err != nil {
			if err == io.EOF {
				return nil, ErrInvalidBinary
			}
			return nil, err
		}
		if n != len(buf) {
			return nil, ErrInvalidBinary
		}
		return (*T)(unsafe.Pointer(&buf[0])), nil
	case *peModule:
		addr := addOffset(r.Base(), rva)
		if addr+szT >= v.Limit() {
			return nil, ErrInvalidBinary
		}
		return (*T)(unsafe.Pointer(addr)), nil
	default:
		return nil, os.ErrInvalid
	}
}

func readStructArray[T any, O constraints.Integer](r peReader, rva O, count int) ([]T, error) {
	szT := reflect.ArrayOf(count, reflect.TypeOf((*T)(nil)).Elem()).Size()
	switch v := r.(type) {
	case *peFile:
		buf := make([]byte, szT)
		n, err := r.ReadAt(buf, int64(rva))
		if err != nil {
			if err == io.EOF {
				return nil, ErrInvalidBinary
			}
			return nil, err
		}
		if n != len(buf) {
			return nil, ErrInvalidBinary
		}
		return unsafe.Slice((*T)(unsafe.Pointer(&buf[0])), count), nil
	case *peModule:
		addr := addOffset(r.Base(), rva)
		if addr+szT >= v.Limit() {
			return nil, ErrInvalidBinary
		}
		return unsafe.Slice((*T)(unsafe.Pointer(addr)), count), nil
	default:
		return nil, os.ErrInvalid
	}
}

type peSectionHeader struct {
	dpe.SectionHeader32
}

func (s *peSectionHeader) NameAsString() string {
	for i, c := range s.Name {
		if c == 0 {
			return string(s.Name[:i])
		}
	}

	return string(s.Name[:])
}

func loadHeaders(r peReader) (*PEInfo, error) {
	// Do some initial verification first
	var mz [2]byte
	if _, err := r.ReadAt(mz[:], 0); err != nil {
		return nil, err
	}
	if mz[0] != 'M' || mz[1] != 'Z' {
		return nil, ErrInvalidBinary
	}

	if _, err := r.Seek(offsetIMAGE_DOS_HEADERe_lfanew, io.SeekStart); err != nil {
		return nil, err
	}

	var e_lfanew int32
	if err := binary.Read(r, binary.LittleEndian, &e_lfanew); err != nil {
		return nil, err
	}
	if e_lfanew <= 0 {
		return nil, ErrInvalidBinary
	}
	if addOffset(r.Base(), e_lfanew) >= r.Limit() {
		return nil, ErrInvalidBinary
	}

	var peMagic [4]byte
	if _, err := r.ReadAt(peMagic[:], int64(e_lfanew)); err != nil {
		return nil, err
	}
	if peMagic[0] != 'P' || peMagic[1] != 'E' || peMagic[2] != 0 || peMagic[3] != 0 {
		return nil, ErrInvalidBinary
	}

	fileHeaderOffset := uintptr(e_lfanew) + unsafe.Sizeof(peMagic)
	fileHeader, err := readStruct[dpe.FileHeader](r, fileHeaderOffset)
	if err != nil {
		return nil, err
	}
	if fileHeader.Machine != expectedMachine {
		return nil, ErrUnsupportedMachine
	}

	optionalHeaderOffset := fileHeaderOffset + unsafe.Sizeof(dpe.FileHeader{})
	optionalHeader, err := readStruct[optionalHeader](r, optionalHeaderOffset)
	if err != nil {
		return nil, err
	}
	if optionalHeader.Magic != optionalHeaderMagic {
		return nil, ErrInvalidBinary
	}

	numSections := fileHeader.NumberOfSections
	if numSections > maxNumSections {
		numSections = maxNumSections
	}

	sectionTableRVA := optionalHeaderOffset + uintptr(fileHeader.SizeOfOptionalHeader)
	sections, err := readStructArray[peSectionHeader](r, sectionTableRVA, int(numSections))
	if err != nil {
		return nil, err
	}

	return &PEInfo{r: r, fileHeader: fileHeader, optionalHeader: optionalHeader, sections: sections}, nil
}

func resolveRVA[O constraints.Integer](nfo *PEInfo, rva O) int64 {
	if _, ok := nfo.r.(*peFile); !ok {
		return int64(rva)
	}

	urva := uint32(rva)
	for _, s := range nfo.sections {
		if urva < s.VirtualAddress {
			continue
		}
		if urva >= (s.VirtualAddress + s.VirtualSize) {
			continue
		}
		voff := urva - s.VirtualAddress
		foff := s.PointerToRawData + voff
		if foff >= s.PointerToRawData+s.SizeOfRawData {
			return 0
		}
		return int64(foff)
	}

	return 0
}

func (nfo *PEInfo) dataDirectory() []dpe.DataDirectory {
	cnt := nfo.optionalHeader.NumberOfRvaAndSizes
	if maxCnt := uint32(len(nfo.optionalHeader.DataDirectory)); cnt > maxCnt {
		cnt = maxCnt
	}
	return nfo.optionalHeader.DataDirectory[:cnt]
}

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT         = dpe.IMAGE_DIRECTORY_ENTRY_EXPORT
	IMAGE_DIRECTORY_ENTRY_IMPORT         = dpe.IMAGE_DIRECTORY_ENTRY_IMPORT
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = dpe.IMAGE_DIRECTORY_ENTRY_RESOURCE
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = dpe.IMAGE_DIRECTORY_ENTRY_EXCEPTION
	IMAGE_DIRECTORY_ENTRY_SECURITY       = dpe.IMAGE_DIRECTORY_ENTRY_SECURITY
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = dpe.IMAGE_DIRECTORY_ENTRY_BASERELOC
	IMAGE_DIRECTORY_ENTRY_DEBUG          = dpe.IMAGE_DIRECTORY_ENTRY_DEBUG
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = dpe.IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = dpe.IMAGE_DIRECTORY_ENTRY_GLOBALPTR
	IMAGE_DIRECTORY_ENTRY_TLS            = dpe.IMAGE_DIRECTORY_ENTRY_TLS
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = dpe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = dpe.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
	IMAGE_DIRECTORY_ENTRY_IAT            = dpe.IMAGE_DIRECTORY_ENTRY_IAT
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = dpe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = dpe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
)

// DataDirectoryEntry returns information from nfo's data directory at index idx.
// idx must be one of the IMAGE_DIRECTORY_ENTRY_* constants in the debug/pe package.
// The type of the return value depends on the value of idx. Most values for idx
// currently return the debug/pe.DataDirectory entry itself, however the
// following idx values, when present, return more sophisticated information:
//
// debug/pe.IMAGE_DIRECTORY_ENTRY_SECURITY returns []AuthenticodeCert;
// debug/pe.IMAGE_DIRECTORY_ENTRY_DEBUG returns []IMAGE_DEBUG_DIRECTORY
//
// Note that other idx values WILL be modified in the future to support more
// sophisticated return values, so be careful to structure your type assertions
// accordingly.
func (nfo *PEInfo) DataDirectoryEntry(idx int) (any, error) {
	dd := nfo.dataDirectory()
	if idx >= len(dd) {
		return nil, ErrIndexOutOfRange
	}

	dde := dd[idx]
	if dde.VirtualAddress == 0 || dde.Size == 0 {
		return nil, ErrNotPresent
	}

	switch idx {
	/* TODO(aaron): (don't forget to sync tests!)
	case dpe.IMAGE_DIRECTORY_ENTRY_EXPORT:
	case dpe.IMAGE_DIRECTORY_ENTRY_IMPORT:
	case dpe.IMAGE_DIRECTORY_ENTRY_RESOURCE:
	*/
	case dpe.IMAGE_DIRECTORY_ENTRY_SECURITY:
		return nfo.extractAuthenticode(dde)
	case dpe.IMAGE_DIRECTORY_ENTRY_DEBUG:
		return nfo.extractDebugInfo(dde)
	// case dpe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
	default:
		return dde, nil
	}
}

// WIN_CERT_REVISION is an enumeration from the Windows SDK.
type WIN_CERT_REVISION uint16

const (
	WIN_CERT_REVISION_1_0 WIN_CERT_REVISION = 0x0100
	WIN_CERT_REVISION_2_0 WIN_CERT_REVISION = 0x0200
)

// WIN_CERT_TYPE is an enumeration from the Windows SDK.
type WIN_CERT_TYPE uint16

const (
	WIN_CERT_TYPE_X509             WIN_CERT_TYPE = 0x0001
	WIN_CERT_TYPE_PKCS_SIGNED_DATA WIN_CERT_TYPE = 0x0002
	WIN_CERT_TYPE_TS_STACK_SIGNED  WIN_CERT_TYPE = 0x0004
)

type _WIN_CERTIFICATE_HEADER struct {
	Length          uint32
	Revision        WIN_CERT_REVISION
	CertificateType WIN_CERT_TYPE
}

// AuthenticodeCert represents an authenticode signature that has been extracted
// from a signed PE binary but not fully parsed.
type AuthenticodeCert struct {
	header _WIN_CERTIFICATE_HEADER
	data   []byte
}

// Revision returns the revision of ac.
func (ac *AuthenticodeCert) Revision() WIN_CERT_REVISION {
	return ac.header.Revision
}

// Type returns the type of ac.
func (ac *AuthenticodeCert) Type() WIN_CERT_TYPE {
	return ac.header.CertificateType
}

// Data returns the raw bytes of ac's cert.
func (ac *AuthenticodeCert) Data() []byte {
	return ac.data
}

func alignUp[V constraints.Integer](v V, powerOfTwo V) V {
	if v < 0 || powerOfTwo < 0 || bits.OnesCount(uint(powerOfTwo)) != 1 {
		panic("invalid arguments to alignUp")
	}
	return v + ((-v) & (powerOfTwo - 1))
}

// IMAGE_DEBUG_DIRECTORY describes debug information embedded in the binary.
type IMAGE_DEBUG_DIRECTORY struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32 // an IMAGE_DEBUG_TYPE constant
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32
}

// IMAGE_DEBUG_TYPE_CODEVIEW identifies the current IMAGE_DEBUG_DIRECTORY as
// pointing to CodeView debug information.
const IMAGE_DEBUG_TYPE_CODEVIEW = 2

// IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED contains CodeView debug information
// embedded in the PE file. Note that this structure's ABI does not match its C
// counterpart because the latter is packed.
type IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED struct {
	GUID    windows.GUID
	Age     uint32
	PDBPath string
}

// String returns the data from u formatted in the same way that Microsoft
// debugging tools and symbol servers use to identify PDB files corresponding
// to a specific binary.
func (u *IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%08X%04X%04X", u.GUID.Data1, u.GUID.Data2, u.GUID.Data3)
	for _, v := range u.GUID.Data4 {
		fmt.Fprintf(&b, "%02X", v)
	}
	fmt.Fprintf(&b, "%X", u.Age)
	return b.String()
}

func (u *IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED) unpack(r *bufio.Reader) error {
	var signature uint32
	if err := binary.Read(r, binary.LittleEndian, &signature); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &u.GUID); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &u.Age); err != nil {
		return err
	}

	var pdbBytes []byte
	for b, err := r.ReadByte(); err == nil && b != 0; b, err = r.ReadByte() {
		pdbBytes = append(pdbBytes, b)
	}

	u.PDBPath = string(pdbBytes)
	return nil
}

func (nfo *PEInfo) extractDebugInfo(dde dpe.DataDirectory) (any, error) {
	count := dde.Size / uint32(unsafe.Sizeof(IMAGE_DEBUG_DIRECTORY{}))
	return readStructArray[IMAGE_DEBUG_DIRECTORY](nfo.r, resolveRVA(nfo, dde.VirtualAddress), int(count))
}

// ExtractCodeViewInfo obtains CodeView debug information from de, assuming that
// de represents CodeView debug info.
func (nfo *PEInfo) ExtractCodeViewInfo(de IMAGE_DEBUG_DIRECTORY) (*IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED, error) {
	if de.Type != IMAGE_DEBUG_TYPE_CODEVIEW {
		return nil, ErrNotCodeView
	}

	cv := new(IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED)
	var sr *io.SectionReader
	switch v := nfo.r.(type) {
	case *peFile:
		sr = io.NewSectionReader(v, int64(de.PointerToRawData), int64(de.SizeOfData))
	case *peModule:
		sr = io.NewSectionReader(v, int64(de.AddressOfRawData), int64(de.SizeOfData))
	default:
		return nil, ErrInvalidBinary
	}

	if err := cv.unpack(bufio.NewReader(sr)); err != nil {
		return nil, err
	}

	return cv, nil
}

func (nfo *PEInfo) extractAuthenticode(dde dpe.DataDirectory) (any, error) {
	if _, ok := nfo.r.(*peFile); !ok {
		// Authenticode; only available in file, not loaded at runtime.
		return nil, ErrUnavailableInModule
	}

	var result []AuthenticodeCert
	// The VirtualAddress is a file offset.
	sr := io.NewSectionReader(nfo.r, int64(dde.VirtualAddress), int64(dde.Size))
	var curOffset int64
	szEntry := unsafe.Sizeof(AuthenticodeCert{})

	for {
		var entry AuthenticodeCert
		if err := binary.Read(sr, binary.LittleEndian, &entry.header); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		curOffset += int64(szEntry)

		entry.data = make([]byte, uintptr(entry.header.Length)-szEntry)
		n, err := sr.Read(entry.data)
		if err != nil {
			// No EOF check here since we've already read a header and are expecting data
			return nil, err
		}
		if n != len(entry.data) {
			return nil, fmt.Errorf("%w: want %d, got %d", ErrBadLength, len(entry.data), n)
		}
		curOffset += int64(n)

		result = append(result, entry)

		curOffset = alignUp(curOffset, 8)
		if _, err := sr.Seek(curOffset, io.SeekStart); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	return result, nil
}
