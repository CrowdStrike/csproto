package csproto

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
)

var (
	// ErrTagNotFound is returned by PartialDecodeResult.FieldData() when the specified tag(s) do not
	// exist in the result.
	ErrTagNotFound = fmt.Errorf("the requested tag does not exist in the partial decode result")
)

var emptyPartialResult PartialDecodeResult

// DecodePartial extracts the specified field tags from data without unmarshaling the entire message.
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
func DecodePartial(data []byte, def map[int]any) (res PartialDecodeResult, err error) {
	if len(data) == 0 || len(def) == 0 {
		return emptyPartialResult, nil
	}
	for dec := NewDecoder(data); dec.More(); {
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
		case WireTypeVarint, WireTypeFixed32, WireTypeFixed64:
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
			val = val[SizeOfTagKey(tag):]
			fd.data = append(fd.data, val)
		case WireTypeLengthDelimited:
			val, err := dec.DecodeBytes()
			if err != nil {
				return emptyPartialResult, err
			}
			if subDef, ok := dv.(map[int]any); ok && len(subDef) > 0 {
				// recurse
				subResult, err := DecodePartial(val, subDef)
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

// PartialDecodeResult holds a (possibly nested) mapping of integer field tags to FieldData instances
// which can be used to retrieve typed values for specific Protobuf message fields.
type PartialDecodeResult struct {
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
func (r *PartialDecodeResult) FieldData(tags ...int) (*FieldData, error) {
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
func (r *PartialDecodeResult) getOrAddFieldData(tag int, wt WireType) (*FieldData, error) {
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

// FieldData is a wrapper around partially-decoded Protobuf field data, with accessors for retrieving
// typed values.
//
// All methods potentially return an error because the Protobuf encoding is not self-describing. We
// must instead rely on the consumer having some prior knowledge of the message data and using that
// knowledge to access the fields appropriately.
//
// The XxxValue() methods convert the partially decoded field data into a single value of the appropriate
// Go type. If the decoded message contained repeated data for the field, the last value is returned.]
//
// Similarly, the XxxValues() methods convert the data into a slice of the appropriate Go type. If the
// decoded message contained only a single value, or the field is not defined as repeated, the methods
// return a one-element slice. We err on the side of determinism since it's not possible to distinguish
// between these two scenarios based on only the encoded data.
//
// For both XxxValue() and XxxValues(), if the source data was not of the correct Protobuf wire type
// for the target Go type a [WireTypeMismatchError] error is returned with relevant details.
//
// A zero-valued instance is the equivalent of a varint field with no data. All methods valid for varint
// data will return [ErrTagNotFound] and all others will return a [WireTypeMismatchError].
//
// To avoid panics, any method called on a nil instance returns a zero value and [ErrTagNotFound].
type FieldData struct {
	// holds the Protobuf wire type from the source data
	wt WireType
	// holds either:
	// . one or more []byte values containing the raw bytes from the decoded message for scalar values
	// . a map[int]*FieldData for nested values
	data []any
}

// BoolValue converts the partially-decoded field data into a bool.
//
// Since Protobuf encodes boolean values as integers, any varint-encoded integer value is valid. A value
// of zero is treated as false and any non-zero value is treated as true.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) BoolValue() (bool, error) {
	return scalarValue(fd, WireTypeVarint, func(data []byte) (bool, error) {
		value, _, err := decodeVarint(data)
		if err != nil {
			return false, err
		}
		return value != 0, nil
	})
}

// BoolValues converts the partially-decoded field data into a []bool.
//
// Since Protobuf encodes boolean values as integers, any varint-encoded integer value is valid. A value
// of zero is treated as false and any non-zero value is treated as true.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) BoolValues() ([]bool, error) {
	return sliceValue(fd, WireTypeVarint, func(data []byte) (bool, int, error) {
		v, n, err := decodeVarint(data)
		if err != nil {
			return false, 0, err
		}
		return v != 0, n, nil
	})
}

// StringValue converts the partially-decoded field data into a string.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) StringValue() (string, error) {
	return scalarValue(fd, WireTypeLengthDelimited, func(data []byte) (string, error) {
		return string(data), nil
	})
}

// StringValues converts the partially-decoded field data into a []string.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) StringValues() ([]string, error) {
	return sliceValue(fd, WireTypeLengthDelimited, func(data []byte) (string, int, error) {
		return string(data), len(data), nil
	})
}

// BytesValue converts the partially-decoded field data into a []byte.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) BytesValue() ([]byte, error) {
	return scalarValue(fd, WireTypeLengthDelimited, func(data []byte) ([]byte, error) {
		return data, nil
	})
}

// BytesValues converts the partially-decoded field data into a [][]byte.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) BytesValues() ([][]byte, error) {
	return sliceValue(fd, WireTypeLengthDelimited, func(data []byte) ([]byte, int, error) {
		return data, len(data), nil
	})
}

// UInt32Value converts the partially-decoded field data into a uint32.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) UInt32Value() (uint32, error) {
	return scalarValue(fd, WireTypeVarint, func(data []byte) (uint32, error) {
		value, _, err := decodeVarint(data)
		if err != nil {
			return 0, err
		}
		if value > math.MaxUint32 {
			return 0, ErrValueOverflow
		}
		return uint32(value), nil
	})
}

// UInt32Values converts the partially-decoded field data into a []uint32.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) UInt32Values() ([]uint32, error) {
	return sliceValue(fd, WireTypeVarint, func(data []byte) (uint32, int, error) {
		value, n, err := decodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		if value > math.MaxUint32 {
			return 0, 0, ErrValueOverflow
		}
		return uint32(value), n, nil
	})
}

// Int32Value converts the partially-decoded field data into an int32.
//
// Use this method to retreive values that are defined as int32 in the Protobuf message. Fields that
// are defined as sint32 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt32Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int32Value() (int32, error) {
	return scalarValue(fd, WireTypeVarint, func(data []byte) (int32, error) {
		value, _, err := decodeVarint(data)
		if err != nil {
			return 0, err
		}
		if int64(value) > math.MaxInt32 {
			return 0, ErrValueOverflow
		}
		return int32(value), nil
	})
}

// Int32Values converts the partially-decoded field data into a []int32.
//
// Use this method to retreive values that are defined as int32 in the Protobuf message. Fields that
// are defined as sint32 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int32Values() ([]int32, error) {
	return sliceValue(fd, WireTypeVarint, func(data []byte) (int32, int, error) {
		value, n, err := decodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		if value > math.MaxUint32 {
			return 0, 0, ErrValueOverflow
		}
		return int32(value), n, nil
	})
}

// SInt32Value converts the partially-decoded field data into an int32.
//
// Use this method to retreive values that are defined as sint32 in the Protobuf message. Fields that
// are defined as int32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt32Value() (int32, error) {
	return scalarValue(fd, WireTypeVarint, func(data []byte) (int32, error) {
		value, _, err := decodeZigZag32(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// SInt32Values converts the partially-decoded field data into a []int32.
//
// Use this method to retreive values that are defined as sint32 in the Protobuf message. Fields that
// are defined as int32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt32Values() ([]int32, error) {
	return sliceValue(fd, WireTypeVarint, func(data []byte) (int32, int, error) {
		value, n, err := decodeZigZag32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// UInt64Value converts the partially-decoded field data into a uint64.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) UInt64Value() (uint64, error) {
	return scalarValue(fd, WireTypeVarint, func(data []byte) (uint64, error) {
		value, _, err := decodeVarint(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// UInt64Values converts the partially-decoded field data into a []uint64.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) UInt64Values() ([]uint64, error) {
	return sliceValue(fd, WireTypeVarint, func(data []byte) (uint64, int, error) {
		value, n, err := decodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Int64Value converts the partially-decoded field data into an int64.
//
// Use this method to retreive values that are defined as int64 in the Protobuf message. Fields that
// are defined as sint64 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt64Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int64Value() (int64, error) {
	return scalarValue(fd, WireTypeVarint, func(data []byte) (int64, error) {
		value, _, err := decodeVarint(data)
		if err != nil {
			return 0, err
		}
		return int64(value), nil
	})
}

// Int64Values converts the partially-decoded field data into a []int64.
//
// Use this method to retreive values that are defined as int64 in the Protobuf message. Fields that
// are defined as sint64 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int64Values() ([]int64, error) {
	return sliceValue(fd, WireTypeVarint, func(data []byte) (int64, int, error) {
		value, n, err := decodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return int64(value), n, nil
	})
}

// SInt64Value converts the partially-decoded field data into an int64.
//
// Use this method to retreive values that are defined as sint64 in the Protobuf message. Fields that
// are defined as int64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt64Value() (int64, error) {
	return scalarValue(fd, WireTypeVarint, func(data []byte) (int64, error) {
		value, _, err := decodeZigZag64(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// SInt64Values converts the partially-decoded field data into a []int64.
//
// Use this method to retreive values that are defined as sint64 in the Protobuf message. Fields that
// are defined as int64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt64Values() ([]int64, error) {
	return sliceValue(fd, WireTypeVarint, func(data []byte) (int64, int, error) {
		value, n, err := decodeZigZag64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Fixed32Value converts the partially-decoded field data into a uint32.
//
// Use this method to retreive values that are defined as fixed32 in the Protobuf message. Fields that
// are defined as uint32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed32Value() (uint32, error) {
	return scalarValue(fd, WireTypeFixed32, func(data []byte) (uint32, error) {
		value, _, err := decodeFixed32(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// Fixed32Values converts the partially-decoded field data into a []uint32.
//
// Use this method to retreive values that are defined as fixed32 in the Protobuf message. Fields that
// are defined as uint32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed32Values() ([]uint32, error) {
	return sliceValue(fd, WireTypeFixed32, func(data []byte) (uint32, int, error) {
		value, n, err := decodeFixed32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Fixed64Value converts the partially-decoded field data into a uint64.
//
// Use this method to retreive values that are defined as fixed64 in the Protobuf message. Fields that
// are defined as uint64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed64Value() (uint64, error) {
	return scalarValue(fd, WireTypeFixed64, func(data []byte) (uint64, error) {
		value, _, err := decodeFixed64(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// Fixed64Values converts the partially-decoded field data into a []uint64.
//
// Use this method to retreive values that are defined as fixed64 in the Protobuf message. Fields that
// are defined as uint64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed64Values() ([]uint64, error) {
	return sliceValue(fd, WireTypeFixed64, func(data []byte) (uint64, int, error) {
		value, n, err := decodeFixed64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Float32Value converts the partially-decoded field data into a float32.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) Float32Value() (float32, error) {
	return scalarValue(fd, WireTypeFixed32, func(data []byte) (float32, error) {
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), nil
	})
}

// Float32Values converts the partially-decoded field data into a []float32.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) Float32Values() ([]float32, error) {
	return sliceValue(fd, WireTypeFixed32, func(data []byte) (float32, int, error) {
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), 4, nil
	})
}

// Float64Value converts the partially-decoded field data into a float64.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) Float64Value() (float64, error) {
	return scalarValue(fd, WireTypeFixed64, func(data []byte) (float64, error) {
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), nil
	})
}

// Float64Values converts the partially-decoded field data into a []float64.
//
// See the [FieldData] docs for more specific details about interpreting partially-decoded data.
func (fd *FieldData) Float64Values() ([]float64, error) {
	return sliceValue(fd, WireTypeFixed64, func(data []byte) (float64, int, error) {
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), 8, nil
	})
}

// scalarValue is a helper to convert the partially-decoded field data in fd to a scalar value of
// concrete type T by invoking the provided convertFn.  The wt parameter contains the expected
// Protobuf wire type for a Go value of type T.
func scalarValue[T any](fd *FieldData, wt WireType, convertFn func([]byte) (T, error)) (T, error) {
	var zero T
	if fd == nil || len(fd.data) == 0 {
		return zero, ErrTagNotFound
	}
	if fd.wt != wt {
		return zero, wireTypeMismatchError(fd.wt, wt)
	}
	switch data := fd.data[len(fd.data)-1].(type) {
	case []byte:
		value, err := convertFn(data)
		if err != nil {
			return zero, err
		}
		return value, nil
	case map[int]*FieldData:
		return zero, fmt.Errorf("cannot convert field data for a nested message into %T", zero)
	default:
		// TODO: should this be a panic?
		// . elements of fd.data *SHOULD* always contain either []byte or map[int]*FieldData so this
		//   is a "just in case" path
		return zero, rawValueConversionError[T](data)
	}
}

// sliceValue is a helper to convert the partially-decoded field data in fd to a slice of values of
// concrete type T by successively invoking the provided convertFn to produce each value. The wt parameter
// contains the expected Protobuf wire type for a Go value of type T.
func sliceValue[T any](fd *FieldData, wt WireType, convertFn func([]byte) (T, int, error)) ([]T, error) {
	if fd == nil {
		return nil, ErrTagNotFound
	}
	switch fd.wt {
	// wt is the wire type for values of type T
	// packed repeated fields are always WireTypeLengthDelimited
	case wt, WireTypeLengthDelimited:
		if len(fd.data) == 0 {
			return nil, ErrTagNotFound
		}
		var res []T
		for _, rv := range fd.data {
			switch data := rv.(type) {
			case []byte:
				// data contains 1 or more encoded values of type T
				// . invoke convertFn at each successive offset to extract them
				for offset := 0; offset < len(data); {
					v, n, err := convertFn(data[offset:])
					if err != nil {
						return nil, err
					}
					if n == 0 {
						return nil, ErrInvalidVarintData
					}
					res = append(res, v)
					offset += n
				}
			case map[int]*FieldData:
				var zero T
				return nil, fmt.Errorf("cannot convert field data for a nested message into a %T", zero)
			default:
				// TODO: should this be a panic?
				// . elements of fd.data *SHOULD* always contain either []byte or map[int]*FieldData so this
				//   is a "just in case" path
				return nil, rawValueConversionError[T](data)
			}
		}
		return res, nil
	default:
		if wt != WireTypeLengthDelimited {
			return nil, wireTypeMismatchError(fd.wt, WireTypeLengthDelimited, wt)
		}
		return nil, wireTypeMismatchError(fd.wt, WireTypeLengthDelimited)
	}
}

// wireTypeMismatchError constructs a new WireTypeMismatchError error
func wireTypeMismatchError(got WireType, supported ...WireType) *WireTypeMismatchError {
	var want string
	if len(supported) == 1 {
		want = supported[0].String()
	} else {
		supportedTypes := make([]string, len(supported))
		for i, wt := range supported {
			supportedTypes[i] = wt.String()
		}
		sort.Strings(supportedTypes)
		want = strings.Join(supportedTypes, ",")
	}
	err := WireTypeMismatchError(fmt.Sprintf("wire type %s must be one of: %s", got, want))
	return &err
}

// WireTypeMismatchError is returned when the actual type of a partially decoded Protobuf field does
// not match one of the supported types.
type WireTypeMismatchError string

// Error satisfies the error interface
func (e *WireTypeMismatchError) Error() string {
	if e == nil {
		return ""
	}
	return string(*e)
}

// rawValueConversionError constructs a new RawValueConversionError
func rawValueConversionError[T any](from any) *RawValueConversionError {
	var target T
	msg := fmt.Sprintf("unable to convert raw value (Kind = %s) to %T", reflect.ValueOf(from).Kind().String(), target)
	err := RawValueConversionError(msg)
	return &err
}

// rawValueConversionErrorOld constructs a new RawValueConversionError error.
func rawValueConversionErrorOld[T1, T2 any](from T1, to T2) *RawValueConversionError {
	err := RawValueConversionError(fmt.Sprintf("unable to convert raw value of type %T to %T", from, to))
	return &err
}

// RawValueConversionError is returned when the partially-decoded value for a Protobuf field could not
// be converted to the requested Go type.
type RawValueConversionError string

// Error satisfies the error interface
func (e *RawValueConversionError) Error() string {
	if e == nil {
		return ""
	}
	return string(*e)
}
