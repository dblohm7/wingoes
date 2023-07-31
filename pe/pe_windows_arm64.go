package pe

import (
	dpe "debug/pe"
)

type optionalHeader dpe.OptionalHeader64
type ptrOffset int64

const (
	expectedMachine     = dpe.IMAGE_FILE_MACHINE_ARM64
	optionalHeaderMagic = 0x020B
)
