// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package registry

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go
//go:generate go run golang.org/x/tools/cmd/goimports -w zsyscall_windows.go

//sys regDeleteKeyValue(key registry.Key, subKey *uint16, valueName *uint16) (ret error) = advapi32.RegDeleteKeyValueW
//sys regGetValue(key registry.Key, subKey *uint16, valueName *uint16, flags uint32, valueType *uint32, pData unsafe.Pointer, cbData *uint32) (ret error) = advapi32.RegGetValueW
//sys regSetKeyValue(key registry.Key, subKey *uint16, valueName *uint16, valueType uint32, pData unsafe.Pointer, cbData uint32) (ret error) = advapi32.RegSetKeyValueW
