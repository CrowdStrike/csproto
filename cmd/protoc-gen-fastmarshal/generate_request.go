package main

import (
	"text/template"

	"google.golang.org/protobuf/compiler/protogen"
)

// outputMode defines the output file generation behavior, either a single file or a file per message
type outputMode int

const (
	// outputModeSingleFile indicates that the Go template should be executed once against the
	// full Protobuf descriptor and the results should be written to a single file.
	outputModeSingleFile outputMode = iota
	// outputModeFilePerMessage indicates that the Go template should be executed against
	// each message in the Protobuf description and the results of each should be written to individual
	// files.
	outputModeFilePerMessage
)

// generateRequest defines the various inputs and configuration options used by the template based
// Protobuf code generator
type generateRequest struct {
	ProtoDesc    *protogen.File
	Mode         outputMode
	NameTemplate string
	Funcs        template.FuncMap
	APIVersion   string
}
