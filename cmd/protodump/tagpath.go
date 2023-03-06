package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CrowdStrike/csproto"
)

// tagPath defines a list of integer values that represent a "path" to a particular field in a binary
// Protobuf message.  Integers are used because encoded Protobuf messages do not contain field names,
// only the integer tags defined in the .proto IDL.
//
// Each element in the path represents a field at that level of the encoded message.  A value of 0 is
// used to indicate that the path applies to all fields at that level.
//
// The path "1" refereces the Outer.id field in the example Protobuf IDL below.  Similarly, the path
// "3.2" references the Inner.timestamp field inside of Outer.nested.
//
//	message Outer {
//		int32 id      = 1;
//		string name   = 2;
//		Inner nested = 3;
//	}
//	message Inner {
//		int32 id        = 1;
//		int64 timestamp = 2;
//	}
type tagPath []int

// String returns a string representation of this path.
func (tp tagPath) String() string {
	if len(tp) == 0 {
		return ""
	}
	ss := make([]string, len(tp))
	for i, t := range tp {
		ss[i] = strconv.Itoa(t)
	}
	return strings.Join(ss, ".")
}

// Matches accepts a tag path and returns a boolean value indicating whether or not this path refers
// to the same field as p.
func (tp tagPath) Matches(p tagPath) bool {
	if len(tp) == 0 || len(tp) != len(p) {
		return false
	}
	for i, t := range tp {
		if t != p[i] {
			return false
		}
	}
	return true
}

// tagPaths defines a custom flag.Value implementation for a flag that can store one or more Protobuf
// tag "paths".
type tagPaths struct {
	paths []tagPath
}

// String returns a string representation of the current value.
func (v *tagPaths) String() string {
	if len(v.paths) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, p := range v.paths {
		if i > 0 {
			sb.WriteRune(',')
		}
		for j, tag := range p {
			if j > 0 {
				sb.WriteRune('.')
			}
			sb.WriteString(strconv.Itoa(tag))
		}
	}
	s := sb.String()
	return "[" + s + "]"
}

// Set satisfies the [flag.Value] interface and parses the provided string into a list of one or more
// tag paths and appends them to the stored value.
func (v *tagPaths) Set(value string) error {
	if value == "" {
		return nil
	}
	paths := strings.Split(value, ",")
	for _, p := range paths {
		var thisPath tagPath
		tokens := strings.Split(p, ".")
		for _, t := range tokens {
			tag, err := strconv.Atoi(t)
			if err != nil {
				return fmt.Errorf("invalid tag token, must be a positive integer or \"*\"")
			}
			if tag < 0 || tag > csproto.MaxTagValue {
				return fmt.Errorf("invalid protobuf tag value: %d", tag)
			}
			thisPath = append(thisPath, tag)
		}
		v.paths = append(v.paths, thisPath)
	}
	return nil
}

// ShouldExpand takes a tagPath and returns a boolean value indicating if that path is in the stored list
func (v *tagPaths) ShouldExpand(p tagPath) bool {
	for _, pp := range v.paths {
		if pp.Matches(p) {
			return true
		}
	}
	return false
}

func (v *tagPaths) Matches(p tagPath) bool {
	for _, pp := range v.paths {
		if pp.Matches(p) {
			return true
		}
	}
	return false
}
