// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wingoes

import (
	"strconv"
	"strings"
	"testing"
)

type isVerGETestCase struct {
	lhs  string
	rhs  string
	want bool
}

var isVerGETests = []isVerGETestCase{
	isVerGETestCase{"10.0.0", "10.0.0", true},
	isVerGETestCase{"6.3.0", "6.2.0", true},
	isVerGETestCase{"6.2.0", "6.3.0", false},
	isVerGETestCase{"1.2.3", "1.1.6", true},
	isVerGETestCase{"1.2.3", "2.3.0", false},
}

func splitVerStr(t *testing.T, vs string) (result [3]uint32) {
	parts := strings.Split(vs, ".")
	if len(parts) != 3 {
		t.Fatalf("Version string %q cannot be split into 3 components", vs)
	}
	for i, p := range parts {
		u, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			t.Fatalf("Version string %q cannot convert component %q: %v", vs, p, err)
		}
		result[i] = uint32(u)
	}
	return result
}

func TestIsVerGE(t *testing.T) {
	for _, tc := range isVerGETests {
		lhs := splitVerStr(t, tc.lhs)
		rhs := splitVerStr(t, tc.rhs)
		got := isVerGE(lhs[0], rhs[0], lhs[1], rhs[1], lhs[2], rhs[2])
		if got != tc.want {
			t.Errorf("test case %q >= %q: got %v, want %v",
				tc.lhs, tc.rhs, got, tc.want)
		}
	}
}

func TestUBR(t *testing.T) {
	_, err := getUBR()
	if err == nil {
		return
	}
	if !IsWin10OrGreater() {
		t.Skipf("test requires Windows 10 or up")
	}
	t.Errorf("getUBR error: %v", err)
}
