// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wingoes

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestGUIDToString(t *testing.T) {
	testGUID, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}

	winStr := testGUID.String()
	ourStr := guidToString(testGUID)
	if winStr != ourStr {
		t.Errorf("guidToString is buggy: got %s, want %s", ourStr, winStr)
	}
}
