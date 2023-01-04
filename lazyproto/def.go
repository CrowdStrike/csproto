package lazyproto

// NewDef initializes and returns a new Def with mappings for the specified field tags.
func NewDef(tags ...int) *Def {
	d := Def{
		m: map[int]any{},
	}
	for _, t := range tags {
		d.m[t] = nil
	}
	return &d
}

// A Def is an optionally nested mapping of protobuf field tags declaring which values should
// be decoded from a message.  If the value given tag maps to a nested definition and the wire type
// in the message data is WireTypeLengthDelimited, the contents are treated as a nested message and
// the nested mapping is applied to the field data recursively.
type Def struct {
	m map[int]any
}

// Add adds field tags to the mapping and returns the Def
func (d *Def) Add(tags ...int) *Def {
	for _, t := range tags {
		d.m[t] = nil
	}
	return d
}

// AddNested adds a mapping for tag to a nested Def with the specified field tags for the nested message
// and returns the nested Def
func (d *Def) AddNested(tag int, nestedTags ...int) *Def {
	nd := NewDef(nestedTags...)
	d.m[tag] = nd
	return nd
}

// Get returns the mapping value for tag plus a boolean indicating whether or not the mapping existed
func (d *Def) Get(tag int) (any, bool) {
	v, ok := d.m[tag]
	return v, ok
}
