// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package wingoes

import (
	"slices"
	"testing"
)

func TestMultiSZ(t *testing.T) {
	t.Run("Decode", testMultiSZDecode)
	t.Run("EncodeDecode", testMultiSZEncodeDecode)
}

func testMultiSZDecode(t *testing.T) {
	type testCase struct {
		in   []uint16
		want []string
	}
	cases := []testCase{
		{nil, []string{}},
		{[]uint16{}, nil},
		{[]uint16{'A'}, nil},
		{[]uint16{'A', 'A'}, nil},
		{[]uint16{0, 0}, []string{}},
		{[]uint16{'A', 0, 0}, []string{"A"}},
		{[]uint16{'A', 0, 'B', 0, 0}, []string{"A", "B"}},
		{[]uint16{'A', 0, 0, 'B', 0, 0}, []string{"A"}},
	}

	check := func(got, want []string) bool {
		// nil matters for testing purposes
		if got == nil && want != nil || got != nil && want == nil {
			return false
		}
		return slices.Equal(got, want)
	}

	for _, curCase := range cases {
		if got, want := MultiSZDecode(curCase.in), curCase.want; !check(got, want) {
			t.Errorf("MultiSZDecode(%#v): got %#v, want %#v", curCase.in, got, want)
		}
	}
}

func testMultiSZEncodeDecode(t *testing.T) {
	type testCase struct {
		val      []string
		expectOk bool
	}
	cases := []testCase{
		{nil, true},
		{[]string{}, true},
		{[]string{""}, false},
		{[]string{"abc"}, true},
		{[]string{"abc", "def"}, true},
		{[]string{"abc", "", "def"}, false},
		{[]string{"abc", "def", ""}, false},
		{[]string{"", "abc", "def"}, false},
	}

	for _, curCase := range cases {
		enc, err := MultiSZEncode(curCase.val)
		wantEnc, gotEnc := curCase.expectOk, err == nil
		if wantEnc != gotEnc {
			t.Errorf("MultiSZEncode error handling: got %v, want %v", gotEnc, wantEnc)
		}
		if !wantEnc {
			continue
		}

		wantDec, gotDec := curCase.val, MultiSZDecode(enc)
		if !slices.Equal(wantDec, gotDec) {
			t.Errorf("MultiSZDecode got %#v, want %#v", gotDec, wantDec)
		}
	}
}
