package main

import (
	"flag"
	"fmt"
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

	apiVersion     protoAPIVersion
	filePerMessage bool
}

type protoAPIVersion string

func (v protoAPIVersion) String() string {
	return string(v)
}

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

// run executes the code generator with the provided options applied
func run() {
	// setup default run options
	runOptions := options{}

	// define our custom flags
	flags := flag.NewFlagSet("protoc-gen-fastmarshal", flag.ExitOnError)
	flags.Var(&runOptions.apiVersion, "apiversion", "the Protobuf API version to use (v1, v2)")
	flags.StringVar(&runOptions.OutputPath, "dest", "", "the path of the output file to be written")
	flags.BoolVar(&runOptions.Debug, "debug", false, "if true, enable verbose debugging output to stderr")
	flags.BoolVar(&runOptions.filePerMessage, "filepermessage", false, "if true, outputs a separate file for each message")

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
				Mode:         outputModeSingleFile,
				ProtoDesc:    protoFile,
				NameTemplate: nameTemplate,
				Funcs:        codeGenFunctions(protoFile),
				APIVersion:   opts.apiVersion.String(),
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
