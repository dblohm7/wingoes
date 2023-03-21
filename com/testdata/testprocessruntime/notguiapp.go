// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package main

import (
	"fmt"
	"runtime"

	"github.com/dblohm7/wingoes/com"
)

func init() {
	registerInit("NonGUIApp", NonGUIAppInit)
	register("NonGUIApp", NonGUIApp)
}

func NonGUIAppInit() {
	if err = com.StartRuntime(com.ConsoleApp); err != nil {
		fmt.Printf("error: got %v, want nil\n", err)
	}
}

func NonGUIApp() {
	if err != nil {
		return
	}

	if !com.IsCurrentOSThreadMTA() {
		fmt.Println("error: IsCurrentOSThreadMTA got false, want true")
		return
	}

	globalOpts, err := com.CreateInstance[com.GlobalOptions](com.CLSID_GlobalOptions)
	if err != nil {
		fmt.Printf("error: got %v, want nil\n", err)
		return
	}

	val, err := globalOpts.Query(com.COMGLB_EXCEPTION_HANDLING)
	if err != nil {
		fmt.Printf("error: got %v, want nil\n", err)
		return
	}
	if val != com.COMGLB_EXCEPTION_DONOT_HANDLE_ANY {
		fmt.Printf("error: COMGLB_EXCEPTION_HANDLING got %d, want %d\n", val, com.COMGLB_EXCEPTION_DONOT_HANDLE_ANY)
		return
	}

	if !checkBackgroundThread(true) {
		fmt.Println("error: background OS thread is not MTA")
		return
	}

	// Force some COM objects to GC before we exit so that we catch any refcount bugs.
	runtime.GC()

	fmt.Println("OK")
}
