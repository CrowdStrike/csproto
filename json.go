package csproto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	gogojson "github.com/gogo/protobuf/jsonpb"
	gogo "github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/jsonpb"
	protov1 "github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/encoding/protojson"
	protov2 "google.golang.org/protobuf/proto"
)

// JSONMarshaler returns an implementation of the json.Marshaler interface that formats msg to JSON
// using the specified options.
func JSONMarshaler(msg interface{}, opts ...JSONOption) json.Marshaler {
	m := jsonMarshaler{
		msg: msg,
	}
	for _, o := range opts {
		o(&m.opts)
	}
	return &m
}

// jsonMarshaler wraps a Protobuf message and satisfies the json.Marshaler interface
type jsonMarshaler struct {
	msg  interface{}
	opts jsonOptions
}

// compile-time interface check
var _ json.Marshaler = (*jsonMarshaler)(nil)

// MarshalJSON satisfies the json.Marshaler interface
//
// If the wrapped message is nil, or a non-nil interface value holding nil, this method returns nil.
// If the message satisfies the json.Marshaler interface we delegate to it directly.  Otherwise,
// this method calls the appropriate underlying runtime (Gogo vs Google V1 vs Google V2) based on
// the message's actual type.
func (m *jsonMarshaler) MarshalJSON() ([]byte, error) {
	if m.msg == nil || reflect.ValueOf(m.msg).IsNil() {
		return nil, nil
	}

	// call the message's implementation directly, if present
	if jm, ok := m.msg.(json.Marshaler); ok {
		return jm.MarshalJSON()
	}

	var buf bytes.Buffer

	// Gogo message?
	if msg, isGogo := m.msg.(gogo.Message); isGogo {
		jm := gogojson.Marshaler{
			Indent:       m.opts.indent,
			EnumsAsInts:  m.opts.useEnumNumbers,
			EmitDefaults: m.opts.emitZeroValues,
		}
		if err := jm.Marshal(&buf, msg); err != nil {
			return nil, fmt.Errorf("unable to marshal message to JSON: %w", err)
		}
		return buf.Bytes(), nil
	}

	// Google V1 message?
	if msg, isV1 := m.msg.(protov1.Message); isV1 {
		jm := jsonpb.Marshaler{
			Indent:       m.opts.indent,
			EnumsAsInts:  m.opts.useEnumNumbers,
			EmitDefaults: m.opts.emitZeroValues,
		}
		if err := jm.Marshal(&buf, msg); err != nil {
			return nil, fmt.Errorf("unable to marshal message to JSON: %w", err)
		}
		return buf.Bytes(), nil
	}

	// Google V2 message?
	if msg, isV2 := m.msg.(protov2.Message); isV2 {
		mo := protojson.MarshalOptions{
			Indent:          m.opts.indent,
			UseProtoNames:   m.opts.useEnumNumbers,
			EmitUnpopulated: m.opts.emitZeroValues,
		}
		b, err := mo.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal message to JSON: %w", err)
		}
		return b, nil
	}

	return nil, fmt.Errorf("unsupported message type %T", m.msg)
}

// JSONOption defines a function that sets a specific JSON formatting option
type JSONOption func(*jsonOptions)

// JSONIndent returns a JSONOption that configures the JSON indentation.
//
// Passing an empty string disables indentation.  If not empty, indent must consist of only spaces or
// tab characters.
func JSONIndent(indent string) JSONOption {
	return func(opts *jsonOptions) {
		opts.indent = indent
	}
}

// JSONUseEnumNumbers returns a JSON option that enables or disables outputting integer values rather
// than the enum names for enum fields.
func JSONUseEnumNumbers(useNumbers bool) JSONOption {
	return func(opts *jsonOptions) {
		opts.useEnumNumbers = useNumbers
	}
}

// JSONIncludeZeroValues returns a JSON option that enables or disables including zero-valued fields
// in the JSON output.
func JSONIncludeZeroValues(emitZeroValues bool) JSONOption {
	return func(opts *jsonOptions) {
		opts.emitZeroValues = emitZeroValues
	}
}

// jsonOptions defines the JSON formatting options
//
// These options are a subset of those available by each of the three supported runtimes.  The supported
// options consist of the things that are provided by all 3 runtimes in the same manner.  If you need
// the full spectrum of the formatting options you will need to use the appropriate runtime.
//
// The zero value results in no indentation, enum values using the enum names, and not including
// zero-valued fields in the output.
type jsonOptions struct {
	// If set, generate multi-line output such that each field is prefixed by indent and terminated
	// by a newline
	indent string
	// If true, enum fields will be output as integers rather than the enum value names
	useEnumNumbers bool
	// If true, include zero-valued fields in the JSON output
	emitZeroValues bool
}
