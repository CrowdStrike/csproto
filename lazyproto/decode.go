package lazyproto

import (
	"fmt"

	"github.com/CrowdStrike/csproto"
)

var (
	// ErrTagNotFound is returned by PartialDecodeResult.FieldData() when the specified tag(s) do not
	// exist in the result.
	ErrTagNotFound = fmt.Errorf("the requested tag does not exist in the partial decode result")
)

var emptyPartialResult DecodeResult

// Decode extracts the specified field tags from data without unmarshaling the entire message.
// The methods on the returned PartialDecodeResult can be used to retrieve the decoded values.
//
// The def param is an optionally nested mapping of protobuf field tags declaring which values should
// be decoded from the message.  If the wire type for a given tag is WireTypeLengthDelimited and the
// value of def[tag] is another map[int]any, the contents are treated as a nested message and is
// decoded recursively.
//
// The purpose of this API is to avoid fully unmarshalling nested message data when only a small subset
// of field values are needed, so [PartialDecodeResult] and [FieldData] only support extracting
// scalar values or slices of scalar values. Consumers that need to decode entire messages will need
// to use [Unmarshal] instead.
func Decode(data []byte, def map[int]any) (res DecodeResult, err error) {
	if len(data) == 0 || len(def) == 0 {
		return emptyPartialResult, nil
	}
	for dec := csproto.NewDecoder(data); dec.More(); {
		tag, wt, err := dec.DecodeTag()
		if err != nil {
			return emptyPartialResult, err
		}
		dv, want := def[tag]
		if !want {
			if _, err := dec.Skip(tag, wt); err != nil {
				return emptyPartialResult, err
			}
			continue
		}
		switch wt {
		case csproto.WireTypeVarint, csproto.WireTypeFixed32, csproto.WireTypeFixed64:
			// varint, fixed32, and fixed64 could be multiple Go types so
			// grab the raw bytes and defer interpreting them to the consumer/caller
			// . varint -> int32, int64, uint32, uint64, sint32, sint64, bool, enum
			// . fixed32 -> int32, uint32, float32
			// . fixed64 -> int32, uint64, float64
			val, err := dec.Skip(tag, wt)
			if err != nil {
				return emptyPartialResult, err
			}
			fd, err := res.getOrAddFieldData(tag, wt)
			if err != nil {
				return emptyPartialResult, err
			}
			// Skip() returns the entire field contents, both the tag and the value, so we need to skip past the tag
			val = val[csproto.SizeOfTagKey(tag):]
			fd.data = append(fd.data, val)
		case csproto.WireTypeLengthDelimited:
			val, err := dec.DecodeBytes()
			if err != nil {
				return emptyPartialResult, err
			}
			if subDef, ok := dv.(map[int]any); ok && len(subDef) > 0 {
				// recurse
				subResult, err := Decode(val, subDef)
				if err != nil {
					return emptyPartialResult, err
				}
				fd, err := res.getOrAddFieldData(tag, wt)
				if err != nil {
					return emptyPartialResult, err
				}
				fd.data = append(fd.data, subResult.m)
			} else {
				fd, err := res.getOrAddFieldData(tag, wt)
				if err != nil {
					return emptyPartialResult, err
				}
				fd.data = append(fd.data, val)
			}
		default:
			return emptyPartialResult, fmt.Errorf("read unknown/unsupported protobuf wire type (%v)", wt)
		}
	}
	return res, nil
}

// DecodeResult holds a (possibly nested) mapping of integer field tags to FieldData instances
// which can be used to retrieve typed values for specific Protobuf message fields.
type DecodeResult struct {
	m map[int]*FieldData
}

// The FieldData method returns a FieldData instance for the specified tag "path", if it exists.
//
// The tags parameter is a list of one or more integer field tags that act as a "path" to a particular
// field to support retreiving fields from nested messages.  Each value is used to retreieve the field
// data at the corresponding level of nesting, i.e. a value of [1, 2] would return the field data for
// tag 2 within the nested data for tag 1 at the root.
//
// For a Protobuf definition like:
//
//	// example.proto
//	message Example {
//		int64  id     = 1;
//		Nested nested = 2;
//	}
//	message Nested {
//		string name        = 1;
//		string description = 2;
//	}
//
// the fields of the Nested message could be retrieved using:
//
//	// data contains the serialized bytes of a Example Protobuf message
//	def := map[int]any{
//		// field 2 from the outer message
//		2: map[int]any{
//			// fields 1 and 2 from the inner message
//			1: nil,
//			2: nil,
//		},
//	}
//	res, _ := csproto.DecodePartial(data, def)
//	nameData, _ := res.FieldData(2, 1)
//	descriptionData, _ := res.FieldData(2, 2)
func (r *DecodeResult) FieldData(tags ...int) (*FieldData, error) {
	if len(tags) == 0 {
		return nil, fmt.Errorf("at least one tag key must be specified")
	}
	if r == nil || len(r.m) == 0 {
		return nil, ErrTagNotFound
	}
	var (
		fd *FieldData
		ok = true
	)
	for dd := r.m; ok && len(tags) > 0; {
		fd, ok = dd[tags[0]]
		if !ok || len(fd.data) == 0 {
			return nil, ErrTagNotFound
		}
		tags = tags[1:]
		if len(tags) == 0 {
			return fd, nil
		}
		dd, ok = fd.data[0].(map[int]*FieldData)
	}
	return nil, ErrTagNotFound
}

// getOrAddFieldData is a helper to consolidate the logic of checking if a given tag exists in the
// field data map and adding it if not.
func (r *DecodeResult) getOrAddFieldData(tag int, wt csproto.WireType) (*FieldData, error) {
	// first key: add a new entry and return
	if len(r.m) == 0 {
		fd := &FieldData{
			wt: wt,
		}
		r.m = map[int]*FieldData{
			tag: fd,
		}
		return fd, nil
	}
	// if the key doesn't exist, add a new entry
	fd, exists := r.m[tag]
	if !exists {
		fd = &FieldData{
			wt: wt,
		}
		r.m[tag] = fd
	}
	// double-check wire type
	if fd.wt != wt {
		return nil, fmt.Errorf("invalid message data - repeated tag %d w/ different wire types (prev=%v, current=%v)", tag, fd.wt, wt)
	}

	return fd, nil
}
