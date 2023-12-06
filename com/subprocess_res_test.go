// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package com

import (
	"os"

	"github.com/tc-hib/winres"
)

const manifestContents = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
	<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
		<application>
			<supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}" />
			<supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}" />
			<supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}" />
			<supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}" />
			<supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
		</application>
	</compatibility>
</assembly>`

func addManifest(outPath, inPath string) (err error) {
	inf, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inf.Close()

	outf, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer func() {
		outf.Close()
		if err != nil {
			os.Remove(outPath)
		}
	}()

	var rs winres.ResourceSet
	if err := rs.Set(winres.RT_MANIFEST, winres.ID(1), 0, []byte(manifestContents)); err != nil {
		return err
	}

	return rs.WriteToEXE(outf, inf, winres.ForceCheckSum())
}
