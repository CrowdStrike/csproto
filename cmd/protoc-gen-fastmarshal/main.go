package main

import (
	"embed"
	"fmt"
	"os"
	"strings"
)

var (
	version = "unknown"
	commit  = "unknown"
	date    = "unknown"
	builtBy = "unknown"

	usageMsg = `This command is meant to be used as a plug-in to protoc, but supports minimal direct invocation.

Plug-in	Usage: protoc --fastmarshal_out=dest=path/to/output.go:. ./example.proto
	- Parses the Protobuf definition at ./example.proto then ....  The output of the template is written to path/to/output.go

Direct Usage: protoc-gen-protomarshal [version|help]
	- version: writes the version, commit hash, build date, and date/time when the binary was built to stdout
	- help:    shows this help message

Any other parameters passed to the command are invalid.
`
)

//go:embed templates/*
var fastmarshalTemplates embed.FS

func main() {
	switch len(os.Args) {
	case 1:
		run()
		return

	case 2:
		switch strings.ToLower(os.Args[1]) {
		case "version":
			fmt.Printf("version: %s, commit: %s, date: %s, builtBy: %s\n", version, commit, date, builtBy)
			return

		case "help":
			fallthrough
		default:
		}
	default:
	}

	fmt.Printf("%s\n", usageMsg)
}
