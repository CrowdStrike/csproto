package lazyproto

import (
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// NewDef initializes and returns a new Def with mappings for the specified field tags.
func NewDef(tags ...int) Def {
	d := Def(make(map[int]Def, len(tags)))
	for _, t := range tags {
		d[t] = nil
	}
	return d
}

// A Def is an optionally nested mapping of protobuf field tags declaring which values should
// be decoded from a message.  If the value for given tag maps to a nested definition and the wire type
// in the message data is WireTypeLengthDelimited, the contents are treated as a nested message and
// the nested mapping is applied to the field data recursively.
//
// Tags must be valid [Protobuf field tags] (between 1 and 19000 or between 20000 and 536870911).
//
// Because a given tag can map to either a scalar value or a sub-mapping for decoding a nested message,
// we have an edge case where a consumer cannot extract both the bytes of a nested message and individual
// fields.  For this case use a negative tag value to add a mapping that will return the raw bytes of
// the nested message field.
//
//	// extract both the raw bytes of the nested message at field 3 *and* the value of field 1 within
//	// that nested message
//	def := lazyproto.NewDef()
//	_ = def.Tags(-3)
//	_ = def.NestedTag(3, 1)
//	decodeResult, _ := lazyproto.Decode(data, def)
//	...
//	// get the raw bytes
//	fd, _ := decodeResult.FieldData(-3)
//	raw, _ := fd.BytesValue()
//	...
//	// get the value of field 1 within the nested message
//	fd, _ = decodeResult.FieldData(3, 1)
//	v, _ := fd.StringValue()
//	...
//
// [valid Protobuf field tags]: https://developers.google.com/protocol-buffers/docs/proto3#assigning_field_numbers
type Def map[int]Def

// Tags adds one or more field tags to the mapping, replacing any existing mappings, and returns the Def.
func (d Def) Tags(tags ...int) Def {
	for _, t := range tags {
		d[t] = nil
	}
	return d
}

// NestedTag adds a mapping for tag to a nested Def with the specified field tags for the nested message,
// replacing any existing mapping, and returns the nested Def
func (d Def) NestedTag(tag int, nestedTags ...int) Def {
	nd := NewDef(nestedTags...)
	d[tag] = nd
	return nd
}

// Get returns the mapping value for tag plus a boolean indicating whether or not the mapping existed
func (d Def) Get(tag int) (Def, bool) {
	v, ok := d[tag]
	return v, ok
}

// Validate checks that d is structurally and semantically valid and returns an error if it is not.
func (d Def) Validate() error {
	return d.validate()
}

// validate checks that d is valid and returns an error if is it not.
//
// The path parameter should be the tag "path" leading to d if it is for a nested message.
func (d Def) validate(path ...int) error {
	for k, v := range d {
		// negative values are invalid per protowire.Number.IsValid but we use them here so we
		// validate |k|
		n := k
		if n < 0 {
			n = -1 * n
		}
		if n > math.MaxInt32 {
			return fmt.Errorf("invalid field tag (%v) at path %v", k, path)
		}
		if !protowire.Number(n).IsValid() {
			return fmt.Errorf("invalid field tag (%v) at path %v", k, path)
		}
		if v != nil {
			if err := v.validate(append(path, k)...); err != nil {
				return err
			}
		}
	}
	return nil
}
