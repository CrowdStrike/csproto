package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/CrowdStrike/csproto"
)

func main() {
	var (
		inputFile       string
		expandPaths     tagPaths
		stringPaths     tagPaths
		showVersionInfo bool
		showUsage       bool
	)

	fset := flag.NewFlagSet("protodump", flag.ExitOnError)
	fset.Usage = printUsage(fset)
	fset.StringVar(&inputFile, "file", "", "The path to the Protobuf data to be decoded. (optional, reads from stdin if not specified)")
	fset.Var(&expandPaths, "expand", "One or more 'paths' to length-delimited fields in the message that should be expanded (optional)")
	fset.Var(&stringPaths, "strings", "One or more 'paths' to length-delimited fields in the message that contain string data (optional)")
	fset.BoolVar(&showVersionInfo, "version", false, "Shows version information")
	fset.BoolVar(&showUsage, "help", false, "Shows usage information")

	err := fset.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if showUsage {
		fset.Usage()
		return
	}

	if showVersionInfo {
		echoVersion()
		return
	}

	var (
		f *os.File
	)
	if inputFile != "" {
		f, err = os.Open(filepath.Clean(inputFile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open input file %q: %v\n", inputFile, err)
			os.Exit(1)
		}
		defer f.Close()
	} else {
		var fi os.FileInfo
		f = os.Stdin
		fi, err = f.Stat()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unexpected error: %v\n", err)
			os.Exit(1)
		}
		if fi.Size() == 0 {
			fmt.Fprintln(os.Stderr, "No data provided on stdin.  Use '-file' or pass data on stdin.")
			os.Exit(1)
		}
	}
	err = dumpProtoFile(f, &expandPaths, &stringPaths)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

const usageMsg = `protodump - A simple Protobuf binary message decoder

Outputs tag/wire type information, along with values where possible, for binary Protobuf messages.
The message data can be passed in via stdin or using the '-file' command-line flag.

Two additional options are supported for length-delimited fields.  For nested message fields, the
'-expand' flag can be used to "recurse" into those messages.  The '-strings' flag can be used to output
field values as strings instead of raw bytes.  Both parameters accept one or more "tag path" values,
which are dot-separated lists of integer field tags that indicate the nesting structure of the message
data.

Examples:
	cat message.bin | protodump
	protodump -file message.bin
	protodump -file message.bin -expand "3" -expand "4.4" -strings "1,2,3.1,3.2`

func printUsage(fset *flag.FlagSet) func() {
	return func() {
		fmt.Fprintln(os.Stderr, usageMsg)
		fmt.Fprintln(os.Stderr, "\n\nFlags:")
		fset.PrintDefaults()
	}
}

var (
	version = ""
	commit  = "unknown"
	date    = "unknown"
	builtBy = "unknown"
)

func echoVersion() {
	if version == "" {
		info, ok := debug.ReadBuildInfo()
		if ok {
			fmt.Printf("%v\n", info)
			version = info.Main.Version
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					commit = s.Value
				case "vcs.time":
					date = s.Value
				}
			}
			if version == "(devel)" && commit != "unknown" && date != "unknown" {
				ts, err := time.Parse(time.RFC3339, date)
				if err != nil {
					ts = time.Now().UTC()
				}
				shortHash := commit
				if len(shortHash) > 12 {
					shortHash = shortHash[:12]
				}
				version = fmt.Sprintf("v0.0.0-devel-%s-%s", ts.Format("20060102130607"), shortHash)
			}
		}
	}
	fmt.Printf("version: %s\ncommit:  %s\ndate:    %s\nbuiltBy: %s\n", version, commit, date, builtBy)
}

func dumpProtoFile(input io.Reader, expand *tagPaths, stringPaths *tagPaths) error {
	data, err := io.ReadAll(input)
	if err != nil {
		return err
	}
	conf := dumpConfig{
		indent:  0,
		expand:  expand,
		strings: stringPaths,
	}
	return dumpProto(os.Stdout, csproto.NewDecoder(data), tagPath{}, conf)
}

type tagPathMatcher interface {
	Matches(tagPath) bool
}

type dumpConfig struct {
	indent  int
	expand  tagPathMatcher
	strings tagPathMatcher
}

func (conf dumpConfig) isStringField(tp tagPath) bool {
	return conf.strings.Matches(tp)
}

func (conf dumpConfig) shouldExpand(tp tagPath) bool {
	return conf.expand.Matches(tp)
}

func dumpProto(w io.Writer, dec *csproto.Decoder, parentTagPath tagPath, conf dumpConfig) error {
	prefix := strings.Repeat(" ", 2*conf.indent)
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	for dec.More() {
		tag, wireType, err := dec.DecodeTag()
		if err != nil {
			return err
		}

		thisTagPath := append(parentTagPath, tag)

		bw.WriteString(fmt.Sprintf("%stag: %d, wire type: %s\n", prefix, tag, wireType))
		switch wireType {
		case csproto.WireTypeVarint:
			vv, err := dec.DecodeInt64()
			if err != nil {
				return err
			}
			bw.WriteString(fmt.Sprintf("%s  varint: %d\n", prefix, vv))
		case csproto.WireTypeFixed32:
			f32, err := dec.DecodeFixed32()
			if err != nil {
				return err
			}
			bw.WriteString(fmt.Sprintf("%s  fixed32: %d\n", prefix, f32))
		case csproto.WireTypeFixed64:
			f64, err := dec.DecodeFixed64()
			if err != nil {
				return err
			}
			bw.WriteString(fmt.Sprintf("%s  fixed64: %d\n", prefix, f64))
		case csproto.WireTypeLengthDelimited:
			ldv, err := dec.DecodeBytes()
			if err != nil {
				return err
			}
			bw.WriteString(fmt.Sprintf("%s  length: %d\n", prefix, len(ldv)))
			switch {
			case conf.isStringField(thisTagPath):
				bw.WriteString(fmt.Sprintf("%s  string: %s\n", prefix, string(ldv)))
			default:
				bw.WriteString(fmt.Sprintf("%s  [", prefix))
				for i, b := range ldv {
					if i > 0 {
						bw.WriteRune(',')
					}
					bw.WriteString(fmt.Sprintf("0x%02X", b))
				}
				bw.WriteString("]\n")
				if conf.shouldExpand(thisTagPath) {
					bw.Flush()
					conf.indent++
					err = dumpProto(w, csproto.NewDecoder(ldv), thisTagPath, conf)
					conf.indent--
					if err != nil {
						return err
					}
				}
			}
		default:
			dec.Skip(tag, wireType)
			return fmt.Errorf("unrecognized proto wire type (%d)", int(wireType))
		}
	}
	return nil
}
