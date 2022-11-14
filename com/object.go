// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package com

// GenericObject is a struct that wraps any interface that implements the COM ABI.
type GenericObject[A ABI] struct {
	Pp **A
}

// Object is the interface that all garbage-collected instances of COM interfaces
// must implement.
type Object interface {
	// GetIID returns the interface ID for the object. This method may be called
	// on Objects containing the zero value, so its return value must not depend
	// on the value of the method's receiver.
	GetIID() *IID

	// Make converts r to an instance of a garbage-collected COM object. The type
	// of its return value must always match the type of the method's receiver.
	Make(r ABIReceiver) any
}
