package pe

import (
	dpe "debug/pe"
)

type optionalHeader dpe.OptionalHeader32
type ptrOffset int32

const (
	expectedMachine     = dpe.IMAGE_FILE_MACHINE_I386
	optionalHeaderMagic = 0x010B
)
