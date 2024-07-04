package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dblohm7/wingoes/pe"
)

var dumpHeaders bool
var dumpSections bool
var dumpDebugInfo bool

/*
var dumpImports bool
var dumpExports bool
var dumpAuthenticode bool
var dumpWinMD bool
var dumpResources bool
*/

func init() {
	flag.Usage = usage
	flag.BoolVar(&dumpHeaders, "headers", false, "dump essential headers")
	flag.BoolVar(&dumpSections, "sections", false, "dump section headers")
	flag.BoolVar(&dumpDebugInfo, "debuginfo", false, "dump debug info")
	flag.Parse()
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintln(flag.CommandLine.Output(), "  <filePath>\n\tpath to PE file")
}

func usageln(args ...any) {
	fmt.Fprintln(flag.CommandLine.Output(), args...)
	usage()
	os.Exit(2)
}

func usagef(format string, args ...any) {
	fmt.Fprintf(flag.CommandLine.Output(), format, args...)
	usage()
	os.Exit(2)
}

func main() {
	filePath := flag.Arg(0)
	if filePath == "" {
		usageln("No file path provided")
	}

	pef, err := pe.NewPEFromFileName(filePath)
	if err != nil {
		log.Fatalf("error opening %q: %v\n", filePath, err)
	}
	defer pef.Close()

	if dumpHeaders {
		runDumpHeaders(pef)
	}
	if dumpSections {
		runDumpSections(pef)
	}
	if dumpDebugInfo {
		runDumpDebugInfo(pef)
	}
}

func runDumpHeaders(peh *pe.PEHeaders) {
	fmt.Printf("FileHeader:\n\n%#v\n\n", *(peh.FileHeader()))
	fmt.Printf("(more to come)\n\n")
}

func runDumpSections(peh *pe.PEHeaders) {
	sections := peh.Sections()
	fmt.Printf("%d sections:\n\n", len(sections))
	for i, sec := range sections {
		fmt.Printf("Index %2d: %s\n%#v\n\n", i, sec.NameString(), sec)
	}
	fmt.Printf("(more to come)\n\n")
}

func runDumpDebugInfo(peh *pe.PEHeaders) {
	fmt.Printf("(more to come)\n\n")
}
