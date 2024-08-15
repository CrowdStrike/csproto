package prototest

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// ParseAnnotatedHex takes a string containing formatted, indented, and commented (via ;) hexadecimal
// and returns the raw hex bytes by stripping the comments and whitespace.
//
// This function is provided to make it a little easier for humans to create test data.  Consumers will
// still need to be able to create the correct hex bytes for the various test messages based on the required
// Protobuf encoding, but this function allows those bytes to be interleaved with line breaks, indentation,
// and comments.
//
// Each line in the string is processed as follows:
//   - A semi-colon (';') character starts a comment.
//   - Comments and spaces are removed.
//   - The remaining string is treated as a sequence of hex digits, which are parsed using [encoding/hex.DecodeString].
//   - The resulting bytes are appended to the result.
//
// An error is returned if the string contains any characters other than hex digits or spaces that are
// not part of a comment.
//
// As an example, below are 2 equally valid instances of the hex-encoded data for Protobuf message.
// The second, annotated data is more human-friendly.
//
//	Raw Hex:
//		08 64 A2 06 12 08 01 12 0E 30 01 D0 04 01 BA 1F 03 66 6F 6F C0 2E 01
//	Annotated Hex:
//		; Foo message
//		08 				; tag=1, enum
//		  64 			; value=100
//		A2 06 			; tag=100, nested message
//		  12 			; len=18
//		  ; Bar message
//		  08 			; tag=1, uint64
//		    01 			; value=1
//		  12 			; tag=2, bytes (encoded message data)
//		    0E 			; len=14
//			; Baz message
//		    30 			; tag=6, uint32
//		      01 		; value=1
//		    D0 04 		; tag=74, uint64
//		      01 		; value=1
//		    BA 1F 		; tag=503, string
//		      03 		; len=3
//		      66 6F 6F 	; "foo"
//		    C0 2E 		; tag=744, uint32
//		      01 		; value=1
func ParseAnnotatedHex(x string) ([]byte, error) {
	var data []byte
	for i, line := range strings.Split(x, "\n") {
		s := line
		if i := strings.Index(s, ";"); i != -1 {
			s = s[:i]
		}
		s = strings.Map(func(c rune) rune {
			// remove any whitespace characters
			// - not just spaces to account for editors that "helpfully" insert tabs
			if unicode.IsSpace(c) {
				return -1
			}
			return c
		}, s)
		if s == "" {
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid data at line %d: %w", i, err)
		}
		data = append(data, b...)
	}
	return data, nil
}
