package lazyproto

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/CrowdStrike/csproto"
)

// FieldData is a wrapper around lazily-decoded Protobuf field data, with accessors for retrieving
// typed values.
//
// All methods potentially return an error because the Protobuf encoding is not self-describing. We
// must instead rely on the consumer having some prior knowledge of the message data and using that
// knowledge to access the fields appropriately.
//
// The XxxValue() methods convert the lazily decoded field data into a single value of the appropriate
// Go type. If the decoded message contained repeated data for the field, the last value is returned.
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
	wt csproto.WireType
	// holds either:
	// . one or more []byte values containing the raw bytes from the decoded message for single or
	//   repeated scalar values
	// . a map[int]*FieldData for nested values
	data []any
}

// BoolValue converts the lazily-decoded field data into a bool.
//
// Since Protobuf encodes boolean values as integers, any varint-encoded integer value is valid. A value
// of zero is treated as false and any non-zero value is treated as true.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BoolValue() (bool, error) {
	return scalarValue(fd, csproto.WireTypeVarint, func(data []byte) (bool, error) {
		value, _, err := csproto.DecodeVarint(data)
		if err != nil {
			return false, err
		}
		return value != 0, nil
	})
}

// BoolValues converts the lazily-decoded field data into a []bool.
//
// Since Protobuf encodes boolean values as integers, any varint-encoded integer value is valid. A value
// of zero is treated as false and any non-zero value is treated as true.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BoolValues() ([]bool, error) {
	return sliceValue(fd, csproto.WireTypeVarint, func(data []byte) (bool, int, error) {
		v, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return false, 0, err
		}
		return v != 0, n, nil
	})
}

// StringValue converts the lazily-decoded field data into a string.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) StringValue() (string, error) {
	return scalarValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) (string, error) {
		return string(data), nil
	})
}

// StringValues converts the lazily-decoded field data into a []string.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) StringValues() ([]string, error) {
	return sliceValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) (string, int, error) {
		return string(data), len(data), nil
	})
}

// BytesValue converts the lazily-decoded field data into a []byte.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BytesValue() ([]byte, error) {
	return scalarValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) ([]byte, error) {
		return data, nil
	})
}

// BytesValues converts the lazily-decoded field data into a [][]byte.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BytesValues() ([][]byte, error) {
	return sliceValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) ([]byte, int, error) {
		return data, len(data), nil
	})
}

// UInt32Value converts the lazily-decoded field data into a uint32.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) UInt32Value() (uint32, error) {
	return scalarValue(fd, csproto.WireTypeVarint, func(data []byte) (uint32, error) {
		value, _, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, err
		}
		if value > math.MaxUint32 {
			return 0, csproto.ErrValueOverflow
		}
		//nolint: gosec // no overflow given the range check above
		return uint32(value), nil
	})
}

// UInt32Values converts the lazily-decoded field data into a []uint32.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) UInt32Values() ([]uint32, error) {
	return sliceValue(fd, csproto.WireTypeVarint, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		if value > math.MaxUint32 {
			return 0, 0, csproto.ErrValueOverflow
		}
		//nolint: gosec // no overflow given the range check above
		return uint32(value), n, nil
	})
}

// Int32Value converts the lazily-decoded field data into an int32.
//
// Use this method to retreive values that are defined as int32 in the Protobuf message. Fields that
// are defined as sint32 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt32Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int32Value() (int32, error) {
	return scalarValue(fd, csproto.WireTypeVarint, func(data []byte) (int32, error) {
		value, _, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, err
		}
		// ensure the result is within [-math.MaxInt32, math.MaxInt32] when converted to a signed value
		//nolint: gosec // overflow == error
		if i64 := int64(value); i64 > math.MaxInt32 || i64 < math.MinInt32 {
			return 0, csproto.ErrValueOverflow
		}
		//nolint: gosec // no overflow given the range check above
		return int32(value), nil
	})
}

// Int32Values converts the lazily-decoded field data into a []int32.
//
// Use this method to retreive values that are defined as int32 in the Protobuf message. Fields that
// are defined as sint32 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int32Values() ([]int32, error) {
	return sliceValue(fd, csproto.WireTypeVarint, func(data []byte) (int32, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		// ensure the result is within [-math.MaxInt32, math.MaxInt32] when converted to a signed value
		if value > math.MaxUint32 {
			return 0, 0, csproto.ErrValueOverflow
		}
		//nolint: gosec // no overflow given the range check above
		return int32(value), n, nil
	})
}

// SInt32Value converts the lazily-decoded field data into an int32.
//
// Use this method to retreive values that are defined as sint32 in the Protobuf message. Fields that
// are defined as int32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt32Value() (int32, error) {
	return scalarValue(fd, csproto.WireTypeVarint, func(data []byte) (int32, error) {
		value, _, err := csproto.DecodeZigZag32(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// SInt32Values converts the lazily-decoded field data into a []int32.
//
// Use this method to retreive values that are defined as sint32 in the Protobuf message. Fields that
// are defined as int32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt32Values() ([]int32, error) {
	return sliceValue(fd, csproto.WireTypeVarint, func(data []byte) (int32, int, error) {
		value, n, err := csproto.DecodeZigZag32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// UInt64Value converts the lazily-decoded field data into a uint64.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) UInt64Value() (uint64, error) {
	return scalarValue(fd, csproto.WireTypeVarint, func(data []byte) (uint64, error) {
		value, _, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// UInt64Values converts the lazily-decoded field data into a []uint64.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) UInt64Values() ([]uint64, error) {
	return sliceValue(fd, csproto.WireTypeVarint, func(data []byte) (uint64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Int64Value converts the lazily-decoded field data into an int64.
//
// Use this method to retreive values that are defined as int64 in the Protobuf message. Fields that
// are defined as sint64 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt64Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int64Value() (int64, error) {
	return scalarValue(fd, csproto.WireTypeVarint, func(data []byte) (int64, error) {
		value, _, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, err
		}
		//nolint: gosec // no overflow, intentionally converting from uint64 to int64
		return int64(value), nil
	})
}

// Int64Values converts the lazily-decoded field data into a []int64.
//
// Use this method to retreive values that are defined as int64 in the Protobuf message. Fields that
// are defined as sint64 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int64Values() ([]int64, error) {
	return sliceValue(fd, csproto.WireTypeVarint, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		//nolint: gosec // no overflow, intentionally converting from uint64 to int64
		return int64(value), n, nil
	})
}

// SInt64Value converts the lazily-decoded field data into an int64.
//
// Use this method to retreive values that are defined as sint64 in the Protobuf message. Fields that
// are defined as int64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt64Value() (int64, error) {
	return scalarValue(fd, csproto.WireTypeVarint, func(data []byte) (int64, error) {
		value, _, err := csproto.DecodeZigZag64(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// SInt64Values converts the lazily-decoded field data into a []int64.
//
// Use this method to retreive values that are defined as sint64 in the Protobuf message. Fields that
// are defined as int64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt64Values() ([]int64, error) {
	return sliceValue(fd, csproto.WireTypeVarint, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeZigZag64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Fixed32Value converts the lazily-decoded field data into a uint32.
//
// Use this method to retreive values that are defined as fixed32 in the Protobuf message. Fields that
// are defined as uint32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed32Value() (uint32, error) {
	return scalarValue(fd, csproto.WireTypeFixed32, func(data []byte) (uint32, error) {
		value, _, err := csproto.DecodeFixed32(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// Fixed32Values converts the lazily-decoded field data into a []uint32.
//
// Use this method to retreive values that are defined as fixed32 in the Protobuf message. Fields that
// are defined as uint32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed32Values() ([]uint32, error) {
	return sliceValue(fd, csproto.WireTypeFixed32, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeFixed32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Fixed64Value converts the lazily-decoded field data into a uint64.
//
// Use this method to retreive values that are defined as fixed64 in the Protobuf message. Fields that
// are defined as uint64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Value() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed64Value() (uint64, error) {
	return scalarValue(fd, csproto.WireTypeFixed64, func(data []byte) (uint64, error) {
		value, _, err := csproto.DecodeFixed64(data)
		if err != nil {
			return 0, err
		}
		return value, nil
	})
}

// Fixed64Values converts the lazily-decoded field data into a []uint64.
//
// Use this method to retreive values that are defined as fixed64 in the Protobuf message. Fields that
// are defined as uint64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed64Values() ([]uint64, error) {
	return sliceValue(fd, csproto.WireTypeFixed64, func(data []byte) (uint64, int, error) {
		value, n, err := csproto.DecodeFixed64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
}

// Float32Value converts the lazily-decoded field data into a float32.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float32Value() (float32, error) {
	return scalarValue(fd, csproto.WireTypeFixed32, func(data []byte) (float32, error) {
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), nil
	})
}

// Float32Values converts the lazily-decoded field data into a []float32.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float32Values() ([]float32, error) {
	return sliceValue(fd, csproto.WireTypeFixed32, func(data []byte) (float32, int, error) {
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), 4, nil
	})
}

// Float64Value converts the lazily-decoded field data into a float64.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float64Value() (float64, error) {
	return scalarValue(fd, csproto.WireTypeFixed64, func(data []byte) (float64, error) {
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), nil
	})
}

// Float64Values converts the lazily-decoded field data into a []float64.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float64Values() ([]float64, error) {
	return sliceValue(fd, csproto.WireTypeFixed64, func(data []byte) (float64, int, error) {
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), 8, nil
	})
}

// close releases all internal resources held by fd.
//
// This is unexported because consumers should not call this method directly.  It is called automatically
// by [DecodeResult.Close].
func (fd *FieldData) close() {
	for i, d := range fd.data {
		if sub, ok := d.(map[int]*FieldData); ok && sub != nil {
			for k, v := range sub {
				if v != nil {
					v.close()
				}
				delete(sub, k)
			}
			fieldDataMapPool.Put(sub)
		}
		fd.data[i] = nil
	}
	fd.data = nil
}

// a sync.Pool of field data maps to cut down on repeated small allocations
var fieldDataMapPool = sync.Pool{
	New: func() any {
		return make(map[int]*FieldData)
	},
}

// scalarProtoFieldGoType is a generic constraint that defines the Go types that can be created from
// encoded Protobuf data.
type scalarProtoFieldGoType interface {
	bool | string | []byte | int32 | uint32 | int64 | uint64 | float32 | float64
}

// scalarValue is a helper to convert the lazily-decoded field data in fd to a scalar value of
// concrete type T by invoking the provided convertFn.  The wt parameter contains the expected
// Protobuf wire type for a Go value of type T.
func scalarValue[T scalarProtoFieldGoType](fd *FieldData, wt csproto.WireType, convertFn func([]byte) (T, error)) (T, error) {
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

// sliceValue is a helper to convert the lazily-decoded field data in fd to a slice of values of
// concrete type T by successively invoking the provided convertFn to produce each value. The wt parameter
// contains the expected Protobuf wire type for a Go value of type T.
func sliceValue[T scalarProtoFieldGoType](fd *FieldData, wt csproto.WireType, convertFn func([]byte) (T, int, error)) ([]T, error) {
	if fd == nil {
		return nil, ErrTagNotFound
	}
	switch fd.wt {
	// wt is the wire type for values of type T
	// packed repeated fields are always WireTypeLengthDelimited
	case wt, csproto.WireTypeLengthDelimited:
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
						return nil, csproto.ErrInvalidVarintData
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
		if wt != csproto.WireTypeLengthDelimited {
			return nil, wireTypeMismatchError(fd.wt, csproto.WireTypeLengthDelimited, wt)
		}
		return nil, wireTypeMismatchError(fd.wt, csproto.WireTypeLengthDelimited)
	}
}

// wireTypeMismatchError constructs a new WireTypeMismatchError error
func wireTypeMismatchError(got csproto.WireType, supported ...csproto.WireType) *WireTypeMismatchError {
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

// WireTypeMismatchError is returned when the actual type of a lazily decoded Protobuf field does
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

// RawValueConversionError is returned when the lazily-decoded value for a Protobuf field could not
// be converted to the requested Go type.
type RawValueConversionError string

// Error satisfies the error interface
func (e *RawValueConversionError) Error() string {
	if e == nil {
		return ""
	}
	return string(*e)
}
