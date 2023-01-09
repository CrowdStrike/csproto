package lazyproto

import (
	"fmt"

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

func (d Def) Validate() error {
	return d.validate()
}

func (d Def) validate(path ...int) error {
	for k, v := range d {
		if !protowire.Number(k).IsValid() {
			return fmt.Errorf("invalid field tag (%v) at path %v", k, path)
		}
		if v != nil {
			path = append(path, k)
			if err := v.validate(path...); err != nil {
				return err
			}
		}
	}
	return nil
}
