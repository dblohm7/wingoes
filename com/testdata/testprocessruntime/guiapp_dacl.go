// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/dblohm7/wingoes"
	"github.com/dblohm7/wingoes/com"
	"golang.org/x/sys/windows"
)

func init() {
	registerInit("GUIAppDACL", GUIAppDACLInit)
	register("GUIAppDACL", GUIApp) // We reuse GUIApp for this part of the test
}

func GUIAppDACLInit() {
	var dacl *windows.ACL
	dacl, err = makeDACL()
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	if err = com.StartRuntimeWithDACL(com.GUIApp, dacl); err != nil {
		fmt.Println("error: ", err)
	}
}

const _COM_RIGHTS_EXECUTE = 1

func makeDACL() (*windows.ACL, error) {
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}

	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}

	userSIDs, err := wingoes.CurrentProcessUserSIDs()
	if err != nil {
		return nil, err
	}

	var anyPackage *windows.SID
	if wingoes.IsWin8OrGreater() {
		anyPackage, err = windows.CreateWellKnownSid(windows.WinBuiltinAnyPackageSid)
		if err != nil {
			return nil, err
		}
	}

	localSystemTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_USER,
		windows.TrusteeValueFromSID(localSystem)}

	adminTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
		windows.TrusteeValueFromSID(administrators)}

	userTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
		windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_USER,
		windows.TrusteeValueFromSID(userSIDs.User)}

	ea := []windows.EXPLICIT_ACCESS{
		{
			_COM_RIGHTS_EXECUTE,
			windows.GRANT_ACCESS,
			windows.NO_INHERITANCE,
			localSystemTrustee,
		},
		{
			_COM_RIGHTS_EXECUTE,
			windows.GRANT_ACCESS,
			windows.NO_INHERITANCE,
			adminTrustee,
		},
		{
			_COM_RIGHTS_EXECUTE,
			windows.GRANT_ACCESS,
			windows.NO_INHERITANCE,
			userTrustee,
		},
	}

	if anyPackage != nil {
		anyPackageTrustee := windows.TRUSTEE{nil, windows.NO_MULTIPLE_TRUSTEE,
			windows.TRUSTEE_IS_SID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			windows.TrusteeValueFromSID(anyPackage)}

		ea = append(ea, windows.EXPLICIT_ACCESS{
			_COM_RIGHTS_EXECUTE,
			windows.GRANT_ACCESS,
			windows.NO_INHERITANCE,
			anyPackageTrustee})
	}

	return windows.ACLFromEntries(ea, nil)
}
