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

Usage: protoc --fastmarshal_out=paths=source_relative:. ./example.proto

Supported options (beyond those provided by google.golang.org/protobuf/compiler/protogen):
  apiversion=v1|v2
    - the Protobuf API version to use in the generated code
    - default is v1
  filepermessage=true|false
    - if true, generate a file for each message rather than a single file
    - default is false
  specialname=[name]
    - declare a field name as "special" so that it will be emitted into the generated code with
      a trailing underscore
    - can be specified multiple times for >1 name
    - useful when using Gogo Protobuf and there are message fields called "Size"
  enableunsafedecode=true|false
	- enable using unsafe code to decode string values without making copies for better performance
	- default is false

Direct Usage: protoc-gen-fastmarshal [version|help]
  version: writes the version, commit hash, build info for the binary to stdout
  help:    shows this help message

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
