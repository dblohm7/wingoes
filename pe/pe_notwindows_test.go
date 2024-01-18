// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package pe

import (
	"testing"
)

func testAuthenticodeAgainstSystemAPI(t *testing.T, filename string, certs []AuthenticodeCert) {
	t.Skipf("This test requires Windows")
}

func testDebugInfoAgainstSystemAPI(t *testing.T, filename string, cv *IMAGE_DEBUG_INFO_CODEVIEW_UNPACKED) {
	t.Skipf("This test requires Windows")
}
