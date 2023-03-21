// Copyright (c) 2022 Aaron Klotz & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package com

import (
	"testing"
)

func TestTryAs(t *testing.T) {
	globalOpts, err := CreateInstance[GlobalOptions](CLSID_GlobalOptions)
	if err != nil {
		t.Fatalf("CreateInstance(CLSID_GlobalOptions) error: %v", err)
	}

	unk, err := TryAs[ObjectBase](globalOpts)
	if err != nil {
		t.Fatalf("TryAs(ObjectBase) error: %v", err)
	}

	globalOpts2, err := TryAs[GlobalOptions](unk)
	if err != nil {
		t.Fatalf("TryAs(GlobalOptions) error: %v", err)
	}

	if globalOpts.UnsafeUnwrap() != globalOpts2.UnsafeUnwrap() {
		t.Errorf("globalOpts ABI != globalOpts2 ABI")
	}
}
