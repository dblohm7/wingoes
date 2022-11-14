// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wingoes

import (
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

type hrTestCase struct {
	hr              HRESULT
	expectFacility  hrFacility // only valid when both expectNT and expectCustomer are false
	expectCode      hrCode     // only valid when both expectNT and expectCustomer are false
	expectSucceeded bool
	expectNT        bool
	expectCustomer  bool
}

var hrTestCases = []hrTestCase{
	hrTestCase{hrS_OK, 0, 0, true, false, false},
	hrTestCase{hrTYPE_E_WRONGTYPEKIND, 2, 0x802A, false, false, false},
	hrTestCase{HRESULT(-((0xC0000022 ^ 0xFFFFFFFF) + 1)) | hrFacilityNTBit, 0, 0, false, true, false},
	hrTestCase{HRESULT(-((((syscall.APPLICATION_ERROR + 1) | hrFailBit) ^ 0xFFFFFFFF) + 1)), 0, 0, false, false, true},
	hrTestCase{HRESULT(-((((syscall.APPLICATION_ERROR + 1) | hrFailBit | hrFacilityNTBit) ^ 0xFFFFFFFF) + 1)), 0, 0, false, false, true},
}

func TestHRESULT(t *testing.T) {
	for _, tc := range hrTestCases {
		hr := tc.hr
		if hr.Succeeded() != tc.expectSucceeded {
			t.Errorf("hr 0x%08X Succeeded() got %v, want %v", uint32(hr), hr.Succeeded(), tc.expectSucceeded)
		}
		if hr.Failed() == tc.expectSucceeded {
			t.Errorf("hr 0x%08X Failed() got %v, want %v", uint32(hr), hr.Failed(), !tc.expectSucceeded)
		}
		if hr.isNT() != tc.expectNT {
			t.Errorf("hr 0x%08X isNT() got %v, want %v", uint32(hr), hr.isNT(), tc.expectNT)
		}
		if hr.isCustomer() != tc.expectCustomer {
			t.Errorf("hr 0x%08X isCustomer() got %v, want %v", uint32(hr), hr.isCustomer(), tc.expectCustomer)
		}
		if !hr.isNT() && !hr.isCustomer() {
			if hr.facility() != tc.expectFacility {
				t.Errorf("hr 0x%08X facility() got %v, want %v", uint32(hr), hr.facility(), tc.expectFacility)
			}
			if hr.code() != tc.expectCode {
				t.Errorf("hr 0x%08X code() got %v, want %v", uint32(hr), hr.code(), tc.expectCode)
			}
		}
	}
}

type errorTestCase struct {
	code             any
	expectNewErrorOK bool
	expectHRESULT    bool
	expectErrno      bool
	expectNTStatus   bool
}

var errorTestCases = []errorTestCase{
	errorTestCase{int64(0), false, false, false, false},
	errorTestCase{hrS_OK, true, true, true, true},
	errorTestCase{hrE_POINTER, true, true, false, false},
	errorTestCase{hrE_NOTIMPL, true, true, true, false},
	errorTestCase{windows.STATUS_ACCESS_DENIED, true, true, true, true},
	errorTestCase{windows.ERROR_ACCESS_DENIED, true, true, true, false},
	errorTestCase{Error(hrE_UNEXPECTED), true, true, true, false},
}

func TestNewError(t *testing.T) {
	for _, tc := range errorTestCases {
		err, ok := NewError(tc.code)
		if ok != tc.expectNewErrorOK {
			t.Errorf("NewError(%#v) ok got %v, want %v", tc.code, ok, tc.expectNewErrorOK)
		}
		if !ok {
			continue
		}
		if tc.expectHRESULT != err.IsAvailableAsHRESULT() {
			t.Errorf("NewError(%#v) HRESULT got %v, want %v", tc.code, err.IsAvailableAsHRESULT(), tc.expectHRESULT)
		}
		if tc.expectErrno != err.IsAvailableAsErrno() {
			t.Errorf("NewError(%#v) Errno got %v, want %v", tc.code, err.IsAvailableAsErrno(), tc.expectErrno)
		}
		if tc.expectNTStatus != err.IsAvailableAsNTStatus() {
			t.Errorf("NewError(%#v) NTStatus got %v, want %v", tc.code, err.IsAvailableAsNTStatus(), tc.expectNTStatus)
		}
	}
}
