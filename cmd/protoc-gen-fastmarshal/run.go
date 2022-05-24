package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"google.golang.org/protobuf/compiler/protogen"
)

// options defines the supported configuration options for a generation request
type options struct {
	OutputPath string
	Debug      bool

	ContentTemplate string
	GetFuncMap      func(*protogen.File, bool) template.FuncMap

	apiVersion         protoAPIVersion
	filePerMessage     bool
	specialNames       specialNames
	enableUnsafeDecode bool
}

// protoAPIVersion defines a string flag that can contain either "v1" or "v2"
type protoAPIVersion string

// String returns a string representation of v
func (v protoAPIVersion) String() string {
	return string(v)
}

// Set assigns the value of v from s or returns an error if s contains an invalid value.
func (v *protoAPIVersion) Set(s string) error {
	s = strings.ToLower(s)
	switch s {
	case "v1", "v2":
		*v = protoAPIVersion(s)
		return nil
	default:
		return fmt.Errorf("invalid Protobuf API version: %s", s)
	}
}

// specialNames defines a flag that holds a set of unique strings presenting Protobuf field names
// that are "special" in that they will collide with generated methods on Protobuf message types.
// "Size" is a common example.
type specialNames map[string]struct{}

// String returns a string representation of v, or the string "<none>" if v is nil or empty
func (v specialNames) String() string {
	if len(v) == 0 {
		return "<none>"
	}
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// Set adds one or more values to the set names.
//
// s should contain a comma-delimited list and any leading or trailing whitespace is trimmed from
// each name token
func (v *specialNames) Set(s string) error {
	names := strings.Split(s, ",")
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		(*v)[n] = struct{}{}
	}
	return nil
}

// IsSpecial returns true if n is in the set and false otherwise.
func (v specialNames) IsSpecial(n string) bool {
	if len(v) == 0 {
		return false
	}
	_, found := v[n]
	return found
}

// run executes the code generator with the provided options applied
func run() {
	// setup default run options
	runOptions := options{
		specialNames: make(specialNames),
	}

	// define our custom flags
	flags := flag.NewFlagSet("protoc-gen-fastmarshal", flag.ExitOnError)
	flags.Var(&runOptions.apiVersion, "apiversion", "the Protobuf API version to use (v1, v2)")
	flags.StringVar(&runOptions.OutputPath, "dest", "", "the path of the output file to be written")
	flags.BoolVar(&runOptions.Debug, "debug", false, "if true, enable verbose debugging output to stderr")
	flags.BoolVar(&runOptions.filePerMessage, "filepermessage", false, "if true, outputs a separate file for each message")
	flags.Var(&runOptions.specialNames, "specialname", "if set, specifies field names to be munged in the generated code")
	flags.BoolVar(&runOptions.enableUnsafeDecode, "enableunsafedecode", false, "if true, enables using unsafe code to decode strings for better perf")

	// load and run the generator
	genOptions := protogen.Options{
		ParamFunc: flags.Set,
	}
	genOptions.Run(doGenerate(&runOptions))
}

func doGenerate(opts *options) func(*protogen.Plugin) error {
	return func(plugin *protogen.Plugin) error {
		if len(plugin.Files) == 0 {
			return fmt.Errorf("no files to generate, exiting")
		}

		if opts.apiVersion == "" {
			opts.apiVersion = protoAPIVersion("v1")
		}

		for _, protoFile := range plugin.Files {
			if !protoFile.Generate {
				continue
			}

			// account for per-message output mode
			// - default output template is "[protofile].pb.fm.go"
			// - file-per-message template is "[protofile]_[lower(messagename)].pb.fm.go"
			nameTemplate := protoFile.GeneratedFilenamePrefix + `.pb.fm.go`
			if opts.filePerMessage {
				nameTemplate = protoFile.GeneratedFilenamePrefix + `_{{.Message.Desc.Name | string | lower}}.pb.fm.go`
			}

			req := generateRequest{
				Mode:               outputModeSingleFile,
				ProtoDesc:          protoFile,
				NameTemplate:       nameTemplate,
				APIVersion:         opts.apiVersion.String(),
				SpecialNames:       opts.specialNames,
				EnableUnsafeDecode: opts.enableUnsafeDecode,
			}
			if opts.filePerMessage {
				req.Mode = outputModeFilePerMessage
			}
			if err := generate(plugin, req); err != nil {
				return err
			}
		}
		return nil
	}
}
