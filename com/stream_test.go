// Copyright (c) 2023 Tailscale Inc & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package com

import (
	"io"
	"runtime"
	"testing"

	"golang.org/x/exp/slices"
)

func TestStream(t *testing.T) {
	t.Run("Default", func(t *testing.T) { memoryStream(t, false) })
	t.Run("Legacy", func(t *testing.T) { memoryStream(t, true) })
}

func memoryStream(t *testing.T, useLegacy bool) {
	testStreamForceLegacy = useLegacy
	defer func() {
		testStreamForceLegacy = false
	}()

	empty1, err := NewMemoryStream(nil)
	if err != nil {
		t.Fatalf("Error calling NewMemoryStream(nil): %v", err)
	}
	size, err := getSize(empty1)
	if err != nil {
		t.Fatalf("Error calling getSize: %v", err)
	}
	if size != 0 {
		t.Errorf("Unexpected size, got %d, want 0", size)
	}

	empty2, err := NewMemoryStream([]byte{})
	if err != nil {
		t.Fatalf("Error calling NewMemoryStream(nil): %v", err)
	}
	size, err = getSize(empty2)
	if err != nil {
		t.Fatalf("Error calling getSize: %v", err)
	}
	if size != 0 {
		t.Errorf("Unexpected size, got %d, want 0", size)
	}

	// Only try this on supported 64-bit archs so that the test doesn't run the
	// risk of crashing due to OOM.
	if runtime.GOARCH != "386" {
		tooBig := make([]byte, maxStreamRWLen+1)
		_, err = NewMemoryStream(tooBig)
		if err == nil {
			t.Errorf("Unexpected success creating too-large memory stream")
		}
	}

	values := makeTestBuf(16)
	stream, err := NewMemoryStream(values)
	if err != nil {
		t.Fatalf("Error calling NewMemoryStream(%d): %v", len(values), err)
	}
	size, err = getSize(stream)
	if err != nil {
		t.Fatalf("Error calling getSize: %v", err)
	}
	if size != uint64(len(values)) {
		t.Errorf("Unexpected size, got %d, want %d", size, len(values))
	}
	pos, err := getSeekPos(stream)
	if err != nil {
		t.Fatalf("Error calling getSeekPos: %v", err)
	}
	if pos != 0 {
		t.Errorf("Unexpected seek pos, got %d, want 0", pos)
	}

	readBuf := make([]byte, len(values))
	nRead, err := stream.Read(readBuf)
	if err != nil {
		t.Fatalf("Unexpected error calling Read, got %v, want nil", err)
	}
	if nRead != len(readBuf) {
		t.Errorf("Unexpected number of bytes read, got %v, want %v", nRead, len(readBuf))
	}
	if !slices.Equal(values, readBuf) {
		t.Errorf("Slices not equal")
	}

	pos, err = getSeekPos(stream)
	if err != nil {
		t.Fatalf("Error calling getSeekPos: %v", err)
	}
	if pos != int64(len(values)) {
		t.Errorf("Unexpected seek pos, got %d, want %d", pos, len(values))
	}

	nRead, err = stream.Read(readBuf)
	if err != io.EOF {
		t.Errorf("Unexpected error calling Read, got %v, want %v", err, io.EOF)
	}
	if !slices.Equal(values, readBuf) {
		t.Errorf("Slices not equal")
	}

	pos, err = stream.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Error calling Seek: %v", err)
	}
	if pos != 0 {
		t.Errorf("Unexpected seek pos, got %d, want 0", pos)
	}

	// Chunked read with EOF
	chunk1 := make([]byte, 4)
	chunk2 := make([]byte, len(values))

	nRead, err = stream.Read(chunk1)
	if err != nil {
		t.Fatalf("Unexpected error calling Read, got %v, want nil", err)
	}
	if nRead != len(chunk1) {
		t.Errorf("Unexpected number of bytes read, got %v, want %v", nRead, len(chunk1))
	}
	if !slices.Equal(chunk1, values[:nRead]) {
		t.Errorf("Slices not equal")
	}

	nRead, err = stream.Read(chunk2)
	if err != nil {
		t.Fatalf("Unexpected error calling Read, got %v, want nil", err)
	}
	nDiff := len(values) - len(chunk1)
	if nRead != nDiff {
		t.Errorf("Unexpected number of bytes read, got %v, want %v", nRead, nDiff)
	}
	if !slices.Equal(chunk2[:nRead], values[len(chunk1):len(chunk1)+nRead]) {
		t.Errorf("Slices not equal")
	}

	nRead, err = stream.Read(chunk2[nRead:])
	if err != io.EOF {
		t.Errorf("Unexpected error calling Read, got %v, want %v", err, io.EOF)
	}

	// Chunked write with EOF
	wstream, err := NewMemoryStream(nil)
	if err != nil {
		t.Fatalf("Error calling NewMemoryStream(nil): %v", err)
	}

	if err := wstream.SetSize(uint64(len(values))); err != nil {
		t.Fatalf("Error calling SetSize(%d): %v", len(values), err)
	}

	pos, err = getSeekPos(wstream)
	if err != nil {
		t.Fatalf("Error calling getSeekPos: %v", err)
	}
	if pos != 0 {
		t.Errorf("Unexpected seek pos, got %d, want 0", pos)
	}

	nWritten, err := wstream.Write(chunk1)
	if err != nil {
		t.Fatalf("Unexpected error calling Write, got %v, want nil", err)
	}
	if nWritten != len(chunk1) {
		t.Errorf("Unexpected number of bytes written, got %v, want %v", nWritten, len(chunk1))
	}

	nWritten, err = wstream.Write(chunk2)
	if err != nil {
		t.Fatalf("Unexpected error calling Write, got %v, want nil", err)
	}
	if nWritten != len(chunk2) {
		t.Errorf("Unexpected number of bytes written, got %v, want %v", nWritten, len(chunk2))
	}

	pos, err = wstream.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Error calling Seek: %v", err)
	}
	if pos != 0 {
		t.Errorf("Unexpected seek pos, got %d, want 0", pos)
	}

	readBuf2 := make([]byte, len(chunk1)+len(chunk2))
	nRead, err = wstream.Read(readBuf2)
	if err != nil {
		t.Fatalf("Unexpected error calling Read, got %v, want nil", err)
	}
	if nRead != len(readBuf2) {
		t.Errorf("Unexpected number of bytes read, got %v, want %v", nRead, len(readBuf2))
	}
	if !slices.Equal(append(chunk1, chunk2...), readBuf2) {
		t.Errorf("Slices not equal")
	}

	// Clone, check same buffer contents but different interface pointers
	stream2, err := stream.Clone()
	if err != nil {
		t.Fatalf("Unexpected error calling Clone, got %v, want nil", err)
	}

	pos, err = stream2.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("Error calling Seek: %v", err)
	}
	if pos != 0 {
		t.Errorf("Unexpected seek pos, got %d, want 0", pos)
	}

	values2 := make([]byte, len(values))
	nRead, err = stream2.Read(values2)
	if err != nil {
		t.Fatalf("Unexpected error calling Read, got %v, want nil", err)
	}
	if nRead != len(values2) {
		t.Errorf("Unexpected number of bytes read, got %v, want %v", nRead, len(values2))
	}
	if !slices.Equal(values, values2) {
		t.Errorf("Slices not equal")
	}

	if stream.UnsafeUnwrap() == stream2.UnsafeUnwrap() {
		t.Errorf("Cloned streams wrap identical interface pointers")
	}
}

func getSize(stream Stream) (uint64, error) {
	statstg, err := stream.Stat(STATFLAG_NONAME)
	if err != nil {
		return 0, err
	}

	return statstg.Size, nil
}

func getSeekPos(stream Stream) (int64, error) {
	return stream.Seek(0, io.SeekCurrent)
}

func makeTestBuf(size byte) []byte {
	values := make([]byte, size)
	for i, l := byte(0), byte(len(values)); i < l; i++ {
		values[i] = i
	}
	return values
}
