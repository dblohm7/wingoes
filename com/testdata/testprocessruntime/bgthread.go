// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"runtime"

	"github.com/dblohm7/wingoes/com"
)

func bgThreadCheckMTA(c chan bool) {
	c <- com.IsCurrentOSThreadMTA()
}

func checkBackgroundThread(needLockOSThread bool) bool {
	if needLockOSThread {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}

	c := make(chan bool)
	go bgThreadCheckMTA(c)
	return <-c
}
