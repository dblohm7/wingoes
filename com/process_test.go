// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package com

import (
	"strings"
	"testing"
)

// Each of these tests needs to run as their own process, since StartRuntime
// performs process-wide initialization that is permanent for the remaining
// life of the process.

func TestGUI(t *testing.T) {
	output := strings.TrimSpace(runTestProg(t, "testprocessruntime", "GUIApp"))
	want := "OK"
	if output != want {
		t.Errorf("%s\n", strings.TrimPrefix(output, "error: "))
	}
}

func TestGUIDACL(t *testing.T) {
	output := strings.TrimSpace(runTestProg(t, "testprocessruntime", "GUIAppDACL"))
	want := "OK"
	if output != want {
		t.Errorf("%s\n", strings.TrimPrefix(output, "error: "))
	}
}

func TestNonGUI(t *testing.T) {
	output := strings.TrimSpace(runTestProg(t, "testprocessruntime", "NonGUIApp"))
	want := "OK"
	if output != want {
		t.Errorf("%s\n", strings.TrimPrefix(output, "error: "))
	}
}
