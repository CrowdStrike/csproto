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

// dataPtr represents a sub-slice of the input buffer as an offset/length pair.
// Both fields are plain integers — writes to heap never trigger GC write barriers.
//
// A zero-valued dataPtr is the sentinel for "no data" — hasData() checks
// offset > 0. This is safe because any valid protobuf field value has
// offset >= 1: at least one tag byte always precedes the value in the wire
// format. Callers that construct dataPtr values outside the decode loop
// must ensure offset > 0 for present fields.
type dataPtr struct {
	offset uint32 // byte offset from the input buffer start; 0 = absent
	length uint32 // byte length
}

// hasData reports whether any field data was decoded for this field.
// Uses offset > 0 as the sentinel check — compiles to a single CMPW
// against the zero register on ARM64.
func (dp dataPtr) hasData() bool {
	return dp.offset > 0
}

// bytes reconstructs a []byte from the dataPtr using the given buffer base address.
// The returned slice aliases the original input buffer. For zero-length fields,
// returns a non-nil empty slice (base[offset:offset]) to preserve the distinction
// between "field present but empty" and "field absent".
func (d dataPtr) bytes(base []byte) []byte {
	return base[d.offset : d.offset+d.length]
}

// coldData holds per-field data that is infrequently accessed during the decode loop:
// the parent DecodeResult, repeated entries for repeated fields, and typed
// conversion buffers. Stored behind a pointer so FieldData stays 24 bytes.
type coldData struct {
	// bufPtr points to a shared []byte owned by the parent DecodeResult.
	// All coldData entries in the same result point to the same heap
	// location — decode() writes it once, close() nils it once, with
	// no per-field loop. 8 bytes (pointer) instead of 24 (slice header).
	bufPtr *[]byte

	// repeated stores additional entries for repeated fields (second occurrence onward).
	// Most fields appear exactly once, so this stays nil/empty in the common case.
	repeated []dataPtr

	// buffers holds typed conversion slices for XxxValues() accessors.
	// Non-nil only in unsafe/fast mode (DecoderModeFast).
	buffers *fieldDataBuffers
}

// unsafeAlias reports whether this field may return data that aliases the
// input buffer (unsafe.String, raw slice) instead of copying. True only
// when buffers is non-nil, which is set exclusively by clone(allocBuffers=true)
// in DecoderModeFast. Using a method instead of bare nil checks makes the
// invariant greppable and prevents a future "pre-allocate buffers in safe
// mode" change from accidentally enabling aliasing.
func (c *coldData) unsafeAlias() bool {
	return c.buffers != nil
}

// baseBuf returns the input buffer for dataPtr reconstruction.
func (c *coldData) baseBuf() []byte {
	return *c.bufPtr
}

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
	// --- 24 bytes total: hot fields touched on every decode-loop iteration ---

	// holds the Protobuf wire type from the source data
	wt csproto.WireType // 8 bytes

	// root holds the first (and usually only) field entry inline.
	// For scalar fields this is the only entry — no slice, no pointer chase,
	// no write barrier. A zero-valued root means no data was found for this field.
	root dataPtr // 8 bytes

	// cold points to heap-allocated per-field data that the decode loop infrequently
	// touches: buffer base pointer, repeated entries, and typed conversion buffers.
	// Set once at clone time; never written during decode.
	cold *coldData // 8 bytes
}

// hasData reports whether any field data was decoded for this field.
// A zero-valued root (offset=0, length=0) means no data — this is safe because
// any valid protobuf field value has offset >= 1 (at least one tag byte precedes it).
func (fd *FieldData) hasData() bool {
	return fd != nil && fd.root.hasData()
}

// entryCount returns the number of decoded entries for this field.
func (fd *FieldData) entryCount() int {
	if !fd.hasData() {
		return 0
	}
	return 1 + len(fd.cold.repeated)
}

// lastEntry returns the last decoded entry (protobuf "last write wins" for scalars).
func (fd *FieldData) lastEntry() dataPtr {
	if fd.cold != nil && len(fd.cold.repeated) > 0 {
		return fd.cold.repeated[len(fd.cold.repeated)-1]
	}
	return fd.root
}

// fieldDataBuffers holds the typed reuse slices for FieldData.
// These are only allocated in unsafe/fast mode and are never touched during
// the decode loop itself — only when a caller reads typed values (BoolValues,
// Int64Values, etc.).
type fieldDataBuffers struct {
	boolSlice    []bool
	uint64Slice  []uint64
	int64Slice   []int64
	uint32Slice  []uint32
	int32Slice   []int32
	stringSlice  []string
	float32Slice []float32
	float64Slice []float64
	bytesSlice   [][]byte

	// holds the maximum capacity of the slice values above
	maxCap int
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []bool
	if buf != nil {
		reuse = buf.boolSlice
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, reuse, func(data []byte) (bool, int, error) {
		v, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return false, 0, err
		}
		return v != 0, n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.boolSlice = s
	}
	return s, err
}

// StringValue converts the lazily-decoded field data into a string.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) StringValue() (string, error) {
	return scalarValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) (string, error) {
		if fd.cold.unsafeAlias() {
			return unsafe.String(unsafe.SliceData(data), len(data)), nil
		}
		return string(data), nil
	})
}

// StringValues converts the lazily-decoded field data into a []string.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) StringValues() ([]string, error) {
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []string
	if buf != nil {
		reuse = buf.stringSlice
	}
	s, err := sliceValue(fd, csproto.WireTypeLengthDelimited, reuse, func(data []byte) (string, int, error) {
		if buf != nil {
			return unsafe.String(unsafe.SliceData(data), len(data)), len(data), nil
		}
		return string(data), len(data), nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.stringSlice = s
	}
	return s, err
}

// BytesValue converts the lazily-decoded field data into a []byte.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BytesValue() ([]byte, error) {
	return scalarValue(fd, csproto.WireTypeLengthDelimited, func(data []byte) ([]byte, error) {
		if fd.cold.unsafeAlias() {
			return data, nil
		}
		return slices.Clone(data), nil
	})
}

// BytesValues converts the lazily-decoded field data into a [][]byte.
//
// NOTE: unlike the other XxxValues() methods, BytesValues does not validate
// the wire type. Calling it on a non-LengthDelimited field silently returns
// the raw encoded bytes rather than a WireTypeMismatchError. This matches
// the original pre-refactor behavior and is preserved for backward compatibility.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BytesValues() ([][]byte, error) {
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}

	buf := fd.cold.buffers
	base := fd.cold.baseBuf()

	var output [][]byte
	if buf != nil && buf.bytesSlice != nil {
		output = buf.bytesSlice[:0]
	} else {
		output = make([][]byte, 0, fd.entryCount())
	}

	b := fd.root.bytes(base)
	if buf == nil {
		b = slices.Clone(b)
	}
	output = append(output, b)

	for _, ref := range fd.cold.repeated {
		b := ref.bytes(base)
		if buf == nil {
			b = slices.Clone(b)
		}
		output = append(output, b)
	}

	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(output))
		buf.bytesSlice = output
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []uint32
	if buf != nil {
		reuse = buf.uint32Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, reuse, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		if value > math.MaxUint32 {
			return 0, 0, csproto.ErrValueOverflow
		}
		return uint32(value), n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.uint32Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []int32
	if buf != nil {
		reuse = buf.int32Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, reuse, func(data []byte) (int32, int, error) {
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
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.int32Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []int32
	if buf != nil {
		reuse = buf.int32Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, reuse, func(data []byte) (int32, int, error) {
		value, n, err := csproto.DecodeZigZag32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.int32Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []uint64
	if buf != nil {
		reuse = buf.uint64Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, reuse, func(data []byte) (uint64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.uint64Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []int64
	if buf != nil {
		reuse = buf.int64Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, reuse, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return int64(value), n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.int64Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []int64
	if buf != nil {
		reuse = buf.int64Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeVarint, reuse, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeZigZag64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.int64Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []uint32
	if buf != nil {
		reuse = buf.uint32Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed32, reuse, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeFixed32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.uint32Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []uint64
	if buf != nil {
		reuse = buf.uint64Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed64, reuse, func(data []byte) (uint64, int, error) {
		value, n, err := csproto.DecodeFixed64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.uint64Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []float32
	if buf != nil {
		reuse = buf.float32Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed32, reuse, func(data []byte) (float32, int, error) {
		if len(data) < 4 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), 4, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.float32Slice = s
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	buf := fd.cold.buffers
	var reuse []float64
	if buf != nil {
		reuse = buf.float64Slice
	}
	s, err := sliceValue(fd, csproto.WireTypeFixed64, reuse, func(data []byte) (float64, int, error) {
		if len(data) < 8 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), 8, nil
	})
	if buf != nil {
		buf.maxCap = max(buf.maxCap, cap(s))
		buf.float64Slice = s
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
	if !fd.hasData() {
		return zero, ErrTagNotFound
	}
	if fd.wt != wt {
		return zero, wireTypeMismatchError(fd.wt, wt)
	}
	data := fd.lastEntry().bytes(fd.cold.baseBuf())
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
		if !fd.hasData() {
			return nil, ErrTagNotFound
		}
		if res != nil {
			res = res[:0]
		} else {
			res = make([]T, 0, fd.entryCount())
		}

		// Cache the buffer base address once — avoids repeated calls to
		// fd.cold.baseBuf() per entry in the processEntry closure below.
		base := fd.cold.baseBuf()

		// processEntry decodes one or more values of type T from a single dataPtr entry.
		processEntry := func(d dataPtr) error {
			data := d.bytes(base)
			for offset := 0; offset < len(data); {
				v, n, err := convertFn(data[offset:])
				if err != nil {
					return err
				}
				if n <= 0 {
					return csproto.ErrInvalidVarintData
				}
				res = append(res, v)
				offset += n
			}
			return nil
		}

		// Process root (first/only entry)
		if err := processEntry(fd.root); err != nil {
			return nil, err
		}
		// Process repeated entries (repeated fields, second occurrence onward)
		for _, ref := range fd.cold.repeated {
			if err := processEntry(ref); err != nil {
				return nil, err
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
	if fd == nil || fd.cold == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	if cap(fd.cold.repeated) > n {
		fd.cold.repeated = make([]dataPtr, 0, n)
	}

	buf := fd.cold.buffers
	if buf == nil {
		return
	}

	// if the slices aren't large enough we don't need to reallocate
	if n > buf.maxCap {
		return
	}

	if cap(buf.boolSlice) > n {
		buf.boolSlice = make([]bool, 0, n)
	}
	if cap(buf.uint64Slice) > n {
		buf.uint64Slice = make([]uint64, 0, n)
	}
	if cap(buf.int64Slice) > n {
		buf.int64Slice = make([]int64, 0, n)
	}
	if cap(buf.uint32Slice) > n {
		buf.uint32Slice = make([]uint32, 0, n)
	}
	if cap(buf.int32Slice) > n {
		buf.int32Slice = make([]int32, 0, n)
	}
	if cap(buf.stringSlice) > n {
		buf.stringSlice = make([]string, 0, n)
	}
	if cap(buf.float32Slice) > n {
		buf.float32Slice = make([]float32, 0, n)
	}
	if cap(buf.float64Slice) > n {
		buf.float64Slice = make([]float64, 0, n)
	}
	if cap(buf.bytesSlice) > n {
		buf.bytesSlice = make([][]byte, 0, n)
	}
	buf.maxCap = n
}

// cap returns the capacity of the largest slice within fd
func (fd *FieldData) cap() int {
	if fd == nil || fd.cold == nil {
		return 0
	}
	mc := 0
	if fd.cold.buffers != nil {
		mc = fd.cold.buffers.maxCap
	}
	return max(cap(fd.cold.repeated), mc)
}
