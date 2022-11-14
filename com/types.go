// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package com

import (
	"github.com/dblohm7/wingoes"
	"golang.org/x/sys/windows"
)

// IID is a GUID that represents an interface ID.
type IID windows.GUID

// CLSID is a GUID that represents a class ID.
type CLSID windows.GUID

// AppID is a GUID that represents an application ID.
type AppID windows.GUID

// ServiceID is a GUID that represents a service ID.
type ServiceID windows.GUID

type coMTAUsageCookie windows.Handle

type coCLSCTX uint32

const (
	// We intentionally do not define combinations of these values, as in my experience
	// people don't realize what they're doing when they use those.
	coCLSCTX_INPROC_SERVER = coCLSCTX(0x1)
	coCLSCTX_LOCAL_SERVER  = coCLSCTX(0x4)
	coCLSCTX_REMOTE_SERVER = coCLSCTX(0x10)
)

type coAPTTYPE int32

const (
	coAPTTYPE_CURRENT = coAPTTYPE(-1)
	coAPTTYPE_STA     = coAPTTYPE(0)
	coAPTTYPE_MTA     = coAPTTYPE(1)
	coAPTTYPE_NA      = coAPTTYPE(2)
	coAPTTYPE_MAINSTA = coAPTTYPE(3)
)

type coAPTTYPEQUALIFIER int32

const (
	coAPTTYPEQUALIFIER_NONE               = coAPTTYPEQUALIFIER(0)
	coAPTTYPEQUALIFIER_IMPLICIT_MTA       = coAPTTYPEQUALIFIER(1)
	coAPTTYPEQUALIFIER_NA_ON_MTA          = coAPTTYPEQUALIFIER(2)
	coAPTTYPEQUALIFIER_NA_ON_STA          = coAPTTYPEQUALIFIER(3)
	coAPTTYPEQUALIFIER_NA_ON_IMPLICIT_MTA = coAPTTYPEQUALIFIER(4)
	coAPTTYPEQUALIFIER_NA_ON_MAINSTA      = coAPTTYPEQUALIFIER(5)
	coAPTTYPEQUALIFIER_APPLICATION_STA    = coAPTTYPEQUALIFIER(6)
)

type aptInfo struct {
	apt       coAPTTYPE
	qualifier coAPTTYPEQUALIFIER
}

type soleAuthenticationInfo struct {
	authnSvc uint32
	authzSvc uint32
	authInfo uintptr
}

type soleAuthenticationList struct {
	count    uint32
	authInfo *soleAuthenticationInfo
}

type soleAuthenticationService struct {
	authnSvc      uint32
	authzSvc      uint32
	principalName *uint16
	hr            wingoes.HRESULT
}

type authCapabilities uint32

const (
	authCapNone            = authCapabilities(0)
	authCapMutualAuth      = authCapabilities(1)
	authCapSecureRefs      = authCapabilities(2)
	authCapAccessControl   = authCapabilities(4)
	authCapAppID           = authCapabilities(8)
	authCapDynamic         = authCapabilities(0x10)
	authCapStaticCloaking  = authCapabilities(0x20)
	authCapDynamicCloaking = authCapabilities(0x40)
	authCapAnyAuthority    = authCapabilities(0x80)
	authCapMakeFullsic     = authCapabilities(0x100)
	authCapRequireFullsic  = authCapabilities(0x200)
	authCapAutoImpersonate = authCapabilities(0x400)
	authCapDefault         = authCapabilities(0x800)
	authCapDisableAAA      = authCapabilities(0x1000)
	authCapNoCustomMarshal = authCapabilities(0x2000)
)

type rpcAuthnLevel uint32

const (
	rpcAuthnLevelDefault      = rpcAuthnLevel(0)
	rpcAuthnLevelNone         = rpcAuthnLevel(1)
	rpcAuthnLevelConnect      = rpcAuthnLevel(2)
	rpcAuthnLevelCall         = rpcAuthnLevel(3)
	rpcAuthnLevelPkt          = rpcAuthnLevel(4)
	rpcAuthnLevelPktIntegrity = rpcAuthnLevel(5)
	rpcAuthnLevelPkgPrivacy   = rpcAuthnLevel(6)
)

type rpcImpersonationLevel uint32

const (
	rpcImpLevelDefault     = rpcImpersonationLevel(0)
	rpcImpLevelAnonymous   = rpcImpersonationLevel(1)
	rpcImpLevelIdentify    = rpcImpersonationLevel(2)
	rpcImpLevelImpersonate = rpcImpersonationLevel(3)
	rpcImpLevelDelegate    = rpcImpersonationLevel(4)
)
