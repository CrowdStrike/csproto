package lazyproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strings"
	"unsafe"

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
	// one or more []byte values containing the raw bytes from the decoded message for single or
	//  repeated scalar values
	data [][]byte

	// these are slices that are initialized when creating a new result,
	// they will be reused if the result is closed and put back in the sync.Pool
	// so we can reduce the overall allocations
	boolSlice    []bool
	uint64Slice  []uint64
	int64Slice   []int64
	uint32Slice  []uint32
	int32Slice   []int32
	stringSlice  []string
	float32Slice []float32
	float64Slice []float64

	// holds the Protobuf wire type from the source data
	wt csproto.WireType

	// holds the maximum capacity of the slice values
	maxCap int
	unsafe bool
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
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, fd.boolSlice, func(data []byte) (bool, int, error) {
		v, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return false, 0, err
		}
		return v != 0, n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.boolSlice = s
	}
	return s, err
}

// StringValue converts the lazily-decoded field data into a string.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) StringValue() (string, error) {
	return scalarValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) (string, error) {
		if fd.unsafe {
			return unsafe.String(unsafe.SliceData(data), len(data)), nil
		}
		return string(data), nil
	})
}

// StringValues converts the lazily-decoded field data into a []string.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) StringValues() ([]string, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeLengthDelimited, fd.stringSlice, func(data []byte) (string, int, error) {
		if fd.unsafe {
			return unsafe.String(unsafe.SliceData(data), len(data)), len(data), nil
		}
		return string(data), len(data), nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.stringSlice = s
	}
	return s, err
}

// BytesValue converts the lazily-decoded field data into a []byte.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BytesValue() ([]byte, error) {
	return scalarValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) ([]byte, error) {
		if fd.unsafe {
			return data, nil
		}
		return slices.Clone(data), nil
	})
}

// BytesValues converts the lazily-decoded field data into a [][]byte.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BytesValues() ([][]byte, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	if fd.unsafe {
		return fd.data, nil
	}
	output := make([][]byte, len(fd.data))
	for i := range output {
		output[i] = slices.Clone(fd.data[i])
	}
	return output, nil
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
		return uint32(value), nil
	})
}

// UInt32Values converts the lazily-decoded field data into a []uint32.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) UInt32Values() ([]uint32, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, fd.uint32Slice, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		if value > math.MaxUint32 {
			return 0, 0, csproto.ErrValueOverflow
		}
		return uint32(value), n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.uint32Slice = s
	}
	return s, err
}

// Int32Value converts the lazily-decoded field data into an int32.
//
// Use this method to retrieve values that are defined as int32 in the Protobuf message. Fields that
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
		if i64 := int64(value); i64 > math.MaxInt32 || i64 < math.MinInt32 {
			return 0, csproto.ErrValueOverflow
		}
		return int32(value), nil
	})
}

// Int32Values converts the lazily-decoded field data into a []int32.
//
// Use this method to retrieve values that are defined as int32 in the Protobuf message. Fields that
// are defined as sint32 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int32Values() ([]int32, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, fd.int32Slice, func(data []byte) (int32, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		// ensure the result is within [-math.MaxInt32, math.MaxInt32] when converted to a signed value
		if i64 := int64(value); i64 > math.MaxInt32 || i64 < math.MinInt32 {
			return 0, 0, csproto.ErrValueOverflow
		}
		return int32(value), n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.int32Slice = s
	}
	return s, err
}

// SInt32Value converts the lazily-decoded field data into an int32.
//
// Use this method to retrieve values that are defined as sint32 in the Protobuf message. Fields that
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
// Use this method to retrieve values that are defined as sint32 in the Protobuf message. Fields that
// are defined as int32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt32Values() ([]int32, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, fd.int32Slice, func(data []byte) (int32, int, error) {
		value, n, err := csproto.DecodeZigZag32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.int32Slice = s
	}
	return s, err
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
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, fd.uint64Slice, func(data []byte) (uint64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.uint64Slice = s
	}
	return s, err
}

// Int64Value converts the lazily-decoded field data into an int64.
//
// Use this method to retrieve values that are defined as int64 in the Protobuf message. Fields that
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
		return int64(value), nil
	})
}

// Int64Values converts the lazily-decoded field data into a []int64.
//
// Use this method to retrieve values that are defined as int64 in the Protobuf message. Fields that
// are defined as sint64 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf ZigZag encoding]: https://developers.google.com/protocol-buffers/docs/encoding#signed-ints
func (fd *FieldData) Int64Values() ([]int64, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, fd.int64Slice, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return int64(value), n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.int64Slice = s
	}
	return s, err
}

// SInt64Value converts the lazily-decoded field data into an int64.
//
// Use this method to retrieve values that are defined as sint64 in the Protobuf message. Fields that
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
// Use this method to retrieve values that are defined as sint64 in the Protobuf message. Fields that
// are defined as int64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) SInt64Values() ([]int64, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, fd.int64Slice, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeZigZag64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.int64Slice = s
	}
	return s, err
}

// Fixed32Value converts the lazily-decoded field data into a uint32.
//
// Use this method to retrieve values that are defined as fixed32 in the Protobuf message. Fields that
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
// Use this method to retrieve values that are defined as fixed32 in the Protobuf message. Fields that
// are defined as uint32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed32Values() ([]uint32, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed32, fd.uint32Slice, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeFixed32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.uint32Slice = s
	}
	return s, err
}

// Fixed64Value converts the lazily-decoded field data into a uint64.
//
// Use this method to retrieve values that are defined as fixed64 in the Protobuf message. Fields that
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
// Use this method to retrieve values that are defined as fixed64 in the Protobuf message. Fields that
// are defined as uint64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Values() instead.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
//
// [Protobuf base128 varint encoding]: https://developers.google.com/protocol-buffers/docs/encoding#varints
func (fd *FieldData) Fixed64Values() ([]uint64, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed64, fd.uint64Slice, func(data []byte) (uint64, int, error) {
		value, n, err := csproto.DecodeFixed64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.uint64Slice = s
	}
	return s, err
}

// Float32Value converts the lazily-decoded field data into a float32.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float32Value() (float32, error) {
	return scalarValue(fd, csproto.WireTypeFixed32, func(data []byte) (float32, error) {
		if len(data) < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), nil
	})
}

// Float32Values converts the lazily-decoded field data into a []float32.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float32Values() ([]float32, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed32, fd.float32Slice, func(data []byte) (float32, int, error) {
		if len(data) < 4 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), 4, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.float32Slice = s
	}
	return s, err
}

// Float64Value converts the lazily-decoded field data into a float64.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float64Value() (float64, error) {
	return scalarValue(fd, csproto.WireTypeFixed64, func(data []byte) (float64, error) {
		if len(data) < 8 {
			return 0, io.ErrUnexpectedEOF
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), nil
	})
}

// Float64Values converts the lazily-decoded field data into a []float64.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) Float64Values() ([]float64, error) {
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed64, fd.float64Slice, func(data []byte) (float64, int, error) {
		if len(data) < 8 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), 8, nil
	})
	if fd.unsafe {
		fd.maxCap = max(fd.maxCap, cap(s))
		fd.float64Slice = s
	}
	return s, err
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
	data := fd.data[len(fd.data)-1]
	value, err := convertFn(data)
	if err != nil {
		return zero, err
	}
	return value, nil
}

// sliceValue is a helper to convert the lazily-decoded field data in fd to a slice of values of
// concrete type T by successively invoking the provided convertFn to produce each value. The wt parameter
// contains the expected Protobuf wire type for a Go value of type T.
func sliceValue[T scalarProtoFieldGoType](fd *FieldData, wt csproto.WireType, res []T, convertFn func([]byte) (T, int, error)) ([]T, error) {
	switch fd.wt {
	// wt is the wire type for values of type T
	// packed repeated fields are always WireTypeLengthDelimited
	case wt, csproto.WireTypeLengthDelimited:
		if len(fd.data) == 0 {
			return nil, ErrTagNotFound
		}
		if res != nil {
			res = res[:0]
		} else {
			res = make([]T, 0, len(fd.data))
		}
		for _, data := range fd.data {
			// data contains 1 or more encoded values of type T
			// . invoke convertFn at each successive offset to extract them
			for offset := 0; offset < len(data); {
				v, n, err := convertFn(data[offset:])
				if err != nil {
					return nil, err
				}
				if n <= 0 {
					return nil, csproto.ErrInvalidVarintData
				}
				res = append(res, v)
				offset += n
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

// RawValueConversionError is returned when the lazily-decoded value for a Protobuf field could not
// be converted to the requested Go type.
//
// Deprecated: RawValueConversionError is no longer possible to return
type RawValueConversionError string

// Error satisfies the error interface
func (e *RawValueConversionError) Error() string {
	if e == nil {
		return ""
	}
	return string(*e)
}

// trunc will reduce the capacity of every slice in *FieldData to n
func (fd *FieldData) trunc(n int) {
	if fd == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	if cap(fd.data) > n {
		fd.data = make([][]byte, 0, n)
	}

	// if the slices aren't large enough we don't need to reallocate
	if n > fd.maxCap {
		return
	}

	if cap(fd.boolSlice) > n {
		fd.boolSlice = make([]bool, 0, n)
	}
	if cap(fd.uint64Slice) > n {
		fd.uint64Slice = make([]uint64, 0, n)
	}
	if cap(fd.int64Slice) > n {
		fd.int64Slice = make([]int64, 0, n)
	}
	if cap(fd.uint32Slice) > n {
		fd.uint32Slice = make([]uint32, 0, n)
	}
	if cap(fd.int32Slice) > n {
		fd.int32Slice = make([]int32, 0, n)
	}
	if cap(fd.stringSlice) > n {
		fd.stringSlice = make([]string, 0, n)
	}
	if cap(fd.float32Slice) > n {
		fd.float32Slice = make([]float32, 0, n)
	}
	if cap(fd.float64Slice) > n {
		fd.float64Slice = make([]float64, 0, n)
	}
	fd.maxCap = n
}

// cap returns the capacity of the largest slice within fd
func (fd *FieldData) cap() int {
	if fd == nil {
		return 0
	}
	return max(cap(fd.data), fd.maxCap)
}
