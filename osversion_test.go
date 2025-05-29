// Copyright (c) 2022 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package wingoes

import (
	"iter"
	"sync/atomic"
	"testing"
)

func TestUBR(t *testing.T) {
	_, err := getUBR()
	if err != nil {
		t.Errorf("getUBR error: %v", err)
	}
}

func TestOSVersion(t *testing.T) {
	osv, err := getVersionInfoInternal()
	if err != nil {
		t.Fatalf("getVersionInfoInternal: %v", err)
	}
	if !verCheckManifest(osv) {
		t.Skipf("missing or invalid manifest")
	}

	t.Run("ServerFlags", testServerFlags)
	t.Run("QueryBuild", testQueryBuild)
}

func testServerFlags(t *testing.T) {
	osv, err := getVersionInfoInternal()
	if err != nil {
		t.Fatalf("getVersionInfoInternal: %v", err)
	}

	isDCKnown := osv.ProductType == _VER_NT_DOMAIN_CONTROLLER
	isDCTest := IsWinDomainController()
	if isDCTest != isDCKnown {
		t.Errorf("IsWinDomainController mismatch: got %v, want %v", isDCTest, isDCKnown)
	}

	isServerKnown := isDCKnown || osv.ProductType == _VER_NT_SERVER
	isServerTest := IsWinServer()
	if isServerTest != isServerKnown {
		t.Errorf("IsWinServer mismatch: got %v, want %v", isServerTest, isServerKnown)
	}
}

var build10QueryValues = []Win10BuildConstant{
	Win10BuildRTM,
	Win10Build1511,
	Win10Build1607,
	WinServer2016,
	Win10Build1703,
	Win10Build1709,
	Win10Build1803,
	Win10Build1809,
	Win10Build1903,
	Win10Build1909,
	Win10Build2004,
	Win10Build20H2,
	Win10Build21H1,
	Win10Build21H2,
	Win10Build22H2,
	WinServer2022,
}

var build11QueryValues = []Win11BuildConstant{
	Win11BuildRTM,
	Win11Build22H2,
	Win11Build23H2,
	Win11Build24H2,
	Win11Build25H2,
	Win11Build26H1,
}

func allBuilds() iter.Seq[uint32] {
	return func(yield func(uint32) bool) {
		for _, v := range build10QueryValues {
			if !yield(uint32(v)) {
				return
			}
		}

		for _, v := range build11QueryValues {
			if !yield(uint32(v)) {
				return
			}
		}
	}
}

func testQueryBuild(t *testing.T) {
	osv, err := getVersionInfoInternal()
	if err != nil {
		t.Fatalf("getVersionInfoInternal: %v", err)
	}

	for b := range allBuilds() {
		got := getVersionInfo().isWin10BuildOrGreater(b)
		want := osv.BuildNumber >= b
		if got != want {
			t.Errorf("build comparison mismatch: got %v, want %v", got, want)
		}
	}
}

func verQueryOnlyBuild(build uint32) (bool, error) {
	condMask := verSetConditionMask(0, _VER_BUILDNUMBER, _VER_GREATER_EQUAL)
	osv := _OSVERSIONINFOEX{
		BuildNumber: build,
	}
	return verVerify(&osv, _VER_BUILDNUMBER, condMask)
}

func runQueries(q func(uint32)) {
	for v := range allBuilds() {
		q(v)
	}
}

func BenchmarkVersionQueryDirect(b *testing.B) {
	q := func(build uint32) {
		verQueryBuild(10, 0, build)
	}

	for b.Loop() {
		runQueries(q)
	}
}

func BenchmarkVersionQueryDirectOnlyBuild(b *testing.B) {
	q := func(build uint32) {
		verQueryOnlyBuild(build)
	}

	for b.Loop() {
		runQueries(q)
	}
}

var (
	verMinBuild atomic.Uint32
	verMaxBuild atomic.Uint32
)

func queryAtomicMinMax(build uint32) {
	if verMinBuild.Load() >= build {
		return
	}
	if build >= verMaxBuild.Load() {
		return
	}

	if gt, _ := verQueryBuild(10, 0, build); gt {
		verMinBuild.Store(build)
		return
	}
	verMaxBuild.Store(build)
}

func BenchmarkVersionQueryAtomicMinMax(b *testing.B) {
	for b.Loop() {
		runQueries(queryAtomicMinMax)
	}
}

func BenchmarkVersionQueryGetVersionEx(b *testing.B) {
	osv, err := getVersionInfoInternal()
	if err != nil {
		b.Fatalf("getVersionInfoInternal: %v", err)
	}

	q := func(build uint32) {
		_ = osv.MajorVersion >= 10 || (osv.MajorVersion == 10 && osv.MinorVersion >= 0 || (osv.MinorVersion == 0 && osv.BuildNumber >= build))
	}

	for b.Loop() {
		runQueries(q)
	}
}
