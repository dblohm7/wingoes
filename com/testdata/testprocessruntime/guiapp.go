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
	registerInit("GUIApp", GUIAppInit)
	register("GUIApp", GUIApp)
}

func GUIAppInit() {
	if err = com.StartRuntime(com.GUIApp); err != nil {
		fmt.Println("error: ", err)
	}
}

func GUIApp() {
	if err != nil {
		return
	}

	if !com.IsCurrentOSThreadSTA() {
		fmt.Println("error: IsCurrentOSThreadSTA got false, want true")
		return
	}

	globalOpts, err := com.CreateInstance[com.GlobalOptions](com.CLSID_GlobalOptions)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	val, err := globalOpts.Query(com.COMGLB_EXCEPTION_HANDLING)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
	if val != com.COMGLB_EXCEPTION_DONOT_HANDLE_ANY {
		fmt.Printf("error: COMGLB_EXCEPTION_HANDLING got %d, want %d\n", val, com.COMGLB_EXCEPTION_DONOT_HANDLE_ANY)
		return
	}

	if !checkBackgroundThread(false) {
		fmt.Println("error: background OS thread is not MTA")
		return
	}

	// Force some COM objects to GC before we exit so that we catch any refcount bugs.
	runtime.GC()

	fmt.Println("OK")
}
