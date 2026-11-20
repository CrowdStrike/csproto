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

// sharedState is the per-result state every coldData in a DecodeResult points
// to. It is allocated once in clone() and is stable across pool recycling;
// by-value copies of a result (the deprecated Decode returns one) share it.
type sharedState struct {
	// buf is the input buffer: decode() sets it once, close() nils it once,
	// with no per-field loop. It is the GC root that keeps the input alive
	// while any dataPtr is in use.
	buf []byte

	// maxBuffer is the WithMaxBufferSize limit, or math.MaxInt when no limit
	// is set. This is the only copy: the decode loop, close() and noteCap all
	// read it here. Slices that grow past it are flagged (flagTrunc) and
	// truncated in close().
	maxBuffer int
}

// coldData holds per-field data that is infrequently accessed during the decode loop:
// a pointer to the parent DecodeResult's shared state (input buffer and buffer
// limit), repeated entries for repeated fields, and typed conversion buffers.
// Stored behind a pointer so FieldData stays 24 bytes.
type coldData struct {
	// shared points to the parent DecodeResult's sharedState; every coldData
	// in the same result points to the same one. 8 bytes (pointer) instead
	// of 24 (slice header) plus a per-field copy of the limit.
	shared *sharedState

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
	return c.shared.buf
}

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
// A field with no data returns a zero value and [ErrTagNotFound] from every method, whatever the
// target Go type; the wire type is only checked once data is present, so [WireTypeMismatchError]
// is never returned for an absent field. This covers a nil instance, a zero-valued instance, and a
// field that was defined in the decoder but did not appear in the message.
type FieldData struct {
	// --- 24 bytes total: hot fields touched on every decode-loop iteration ---

	// wt holds the Protobuf wire type from the source data (0-7), or -1
	// after close. One byte instead of an 8-byte csproto.WireType; read it
	// with wireType().
	wt int8 // offset 0

	// flags are per-field bits for close(), kept on this hot cache line
	// (which close() already writes to reset root) so close() follows
	// cold only for fields that actually have something to reset there.
	flags fieldFlags // offset 1

	// root holds the first (and usually only) field entry inline.
	// For scalar fields this is the only entry — no slice, no pointer chase,
	// no write barrier. A zero-valued root means no data was found for this field.
	// dataPtr needs only 4-byte alignment, so it packs after wt/flags.
	root dataPtr // offset 4, 8 bytes

	// cold points to heap-allocated per-field data that the decode loop infrequently
	// touches: buffer base pointer, repeated entries, and typed conversion buffers.
	// Set once at clone time; never written during decode.
	cold *coldData // offset 16, 8 bytes
}

// fieldFlags is a bit field of per-field state that close() must reset in
// coldData. A zero value means close() never loads coldData for the field.
type fieldFlags uint8

const (
	// flagRepeated: the field occurred more than once, so coldData.repeated
	// is non-empty. Set by the decode loop's repeated-field branch.
	flagRepeated fieldFlags = 1 << iota
	// flagAliased: in DecoderModeFast, StringValues/BytesValues cached
	// slices in coldData.buffers whose elements alias the input buffer
	// (unsafe.String / raw sub-slices). close() zeroes them so the pooled
	// result does not pin the input.
	flagAliased
	// flagTrunc: a slice in this field's coldData (repeated or a buffers
	// slice) grew past the WithMaxBufferSize limit. close() truncates the
	// field, so fields under the limit are never touched.
	flagTrunc
)

// noteCap records a cached XxxValues slice capacity in maxCap and flags the
// field for truncation in close() if it grew past the WithMaxBufferSize limit.
// Fast mode only (buffers set).
func (fd *FieldData) noteCap(n int) {
	c := fd.cold
	c.buffers.maxCap = max(c.buffers.maxCap, n)
	if n > c.shared.maxBuffer {
		fd.flags |= flagTrunc
	}
}

// wireType returns the field's Protobuf wire type.
func (fd *FieldData) wireType() csproto.WireType {
	return csproto.WireType(fd.wt)
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

	// maxCap holds the maximum capacity of the slice values above, so the
	// WithBufferFilterFunc walk (cap/trunc) doesn't have to inspect each slice.
	maxCap int
}

// Reuse-slice selectors passed to sliceValue. Each XxxValues accessor names
// the fieldDataBuffers slice it caches into; accessors that share a Go type
// (e.g. Int32Values/SInt32Values) share the same slice.
func boolBuf(b *fieldDataBuffers) *[]bool       { return &b.boolSlice }
func stringBuf(b *fieldDataBuffers) *[]string   { return &b.stringSlice }
func uint32Buf(b *fieldDataBuffers) *[]uint32   { return &b.uint32Slice }
func int32Buf(b *fieldDataBuffers) *[]int32     { return &b.int32Slice }
func uint64Buf(b *fieldDataBuffers) *[]uint64   { return &b.uint64Slice }
func int64Buf(b *fieldDataBuffers) *[]int64     { return &b.int64Slice }
func float32Buf(b *fieldDataBuffers) *[]float32 { return &b.float32Slice }
func float64Buf(b *fieldDataBuffers) *[]float64 { return &b.float64Slice }

// releaseAliases zeroes the cached string and []byte entries so the pooled
// buffers do not keep the previous input buffer reachable after Close. In
// DecoderModeFast these entries are unsafe.String / raw sub-slices that point
// into the input. Clearing [0:len] is sufficient: the reuse paths always
// start from s[:0] and append, so no live entries exist beyond len, and every
// close() clears what the preceding decode wrote. The numeric slices hold no
// pointers and are left untouched.
func (b *fieldDataBuffers) releaseAliases() {
	clear(b.stringSlice)
	b.stringSlice = b.stringSlice[:0]
	clear(b.bytesSlice)
	b.bytesSlice = b.bytesSlice[:0]
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
	return sliceValue(fd, csproto.WireTypeVarint, boolBuf, func(data []byte) (bool, int, error) {
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
	data, err := fd.lengthDelimitedValue()
	if err != nil || len(data) == 0 {
		return "", err // don't alias the input for an empty string
	}
	if fd.cold.unsafeAlias() {
		return unsafe.String(unsafe.SliceData(data), len(data)), nil
	}
	return string(data), nil
}

// StringValues converts the lazily-decoded field data into a []string.
//
// Every occurrence of the field yields exactly one element, including zero-length entries, which
// are returned as "". The result therefore has one element per entry, in wire order, aligned
// index-for-index with [FieldData.BytesValues].
//
// Compatibility note: earlier versions silently dropped zero-length entries, so a repeated field
// encoded as ["a", "", "b"] returned ["a", "b"]. It now returns ["a", "", "b"], matching the
// Protobuf spec; callers that relied on the old length or indexes must account for empty strings.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) StringValues() ([]string, error) {
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	alias := fd.cold.unsafeAlias()
	// Pick a top-level converter rather than a closure capturing alias; see
	// lengthDelimitedValue for why accessor closures must not capture.
	conv := copyString
	if alias {
		conv = aliasString
	}
	// wt is LengthDelimited, so sliceValue treats each entry as exactly one
	// string (strings are never packed), including zero-length entries.
	s, err := sliceValue(fd, csproto.WireTypeLengthDelimited, stringBuf, conv)
	if alias {
		fd.flags |= flagAliased // elements alias the input; see flagAliased
	}
	return s, err
}

// aliasString is the StringValues converter for DecoderModeFast: the result
// aliases data. Empty entries return "" so they don't alias the input.
func aliasString(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, nil
	}
	return unsafe.String(unsafe.SliceData(data), len(data)), len(data), nil
}

// copyString is the StringValues converter for the safe modes: the result is
// a copy of data.
func copyString(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, nil
	}
	return string(data), len(data), nil
}

// BytesValue converts the lazily-decoded field data into a []byte.
//
// See the [FieldData] docs for more specific details about interpreting lazily-decoded data.
func (fd *FieldData) BytesValue() ([]byte, error) {
	data, err := fd.lengthDelimitedValue()
	if err != nil {
		return nil, err
	}
	if fd.cold.unsafeAlias() {
		return data, nil
	}
	return slices.Clone(data), nil
}

// lengthDelimitedValue returns the raw bytes of the last length-delimited entry,
// with the same checks and errors as scalarValue.
//
// StringValue and BytesValue use this instead of scalarValue because their
// conversion depends on fd, which would mean passing scalarValue a closure that
// captures fd. Under profile-guided optimization the accessors get inlined into
// hot callers, the capturing closure escapes, and every call heap-allocates it.
// The same rule applies to every convertFn passed to scalarValue or sliceValue:
// it must not capture anything (StringValues picks a top-level function for
// this reason). No test enforces this; to check it, `go build -gcflags=-m=2
// ./lazyproto` must report no "capturing by value" lines for this file.
func (fd *FieldData) lengthDelimitedValue() ([]byte, error) {
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	if fd.wireType() != csproto.WireTypeLengthDelimited {
		return nil, wireTypeMismatchError(fd.wireType(), csproto.WireTypeLengthDelimited)
	}
	return fd.lastEntry().bytes(fd.cold.baseBuf()), nil
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

	alias := fd.cold.unsafeAlias()
	b := fd.root.bytes(base)
	if !alias {
		b = slices.Clone(b)
	}
	output = append(output, b)

	for _, ref := range fd.cold.repeated {
		b := ref.bytes(base)
		if !alias {
			b = slices.Clone(b)
		}
		output = append(output, b)
	}

	if buf != nil {
		fd.noteCap(cap(output))
		buf.bytesSlice = output
	}
	if alias {
		fd.flags |= flagAliased // elements alias the input; see flagAliased
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
	return sliceValue(fd, csproto.WireTypeVarint, uint32Buf, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		if value > math.MaxUint32 {
			return 0, 0, csproto.ErrValueOverflow
		}
		return uint32(value), n, nil
	})
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
	return sliceValue(fd, csproto.WireTypeVarint, int32Buf, func(data []byte) (int32, int, error) {
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
	return sliceValue(fd, csproto.WireTypeVarint, int32Buf, func(data []byte) (int32, int, error) {
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
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	return sliceValue(fd, csproto.WireTypeVarint, uint64Buf, func(data []byte) (uint64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
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
	return sliceValue(fd, csproto.WireTypeVarint, int64Buf, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeVarint(data)
		if err != nil {
			return 0, 0, err
		}
		return int64(value), n, nil
	})
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
	return sliceValue(fd, csproto.WireTypeVarint, int64Buf, func(data []byte) (int64, int, error) {
		value, n, err := csproto.DecodeZigZag64(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
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
	return sliceValue(fd, csproto.WireTypeFixed32, uint32Buf, func(data []byte) (uint32, int, error) {
		value, n, err := csproto.DecodeFixed32(data)
		if err != nil {
			return 0, 0, err
		}
		return value, n, nil
	})
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
	return sliceValue(fd, csproto.WireTypeFixed64, uint64Buf, func(data []byte) (uint64, int, error) {
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
	return sliceValue(fd, csproto.WireTypeFixed32, float32Buf, func(data []byte) (float32, int, error) {
		if len(data) < 4 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return math.Float32frombits(binary.LittleEndian.Uint32(data)), 4, nil
	})
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
	return sliceValue(fd, csproto.WireTypeFixed64, float64Buf, func(data []byte) (float64, int, error) {
		if len(data) < 8 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), 8, nil
	})
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
	if fd.wireType() != wt {
		return zero, wireTypeMismatchError(fd.wireType(), wt)
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
//
// Data whose wire type is wt yields exactly one value per entry. LengthDelimited data for a
// non-LengthDelimited wt is a packed repeated field, and each entry yields zero or more values.
//
// pick selects this accessor's reuse slice from fd.cold.buffers (e.g. boolBuf); it is only
// called when buffers is non-nil (DecoderModeFast). sliceValue reuses that slice and stores the result back into it,
// even when a conversion fails part-way, so a malformed field doesn't throw away the pooled backing
// array (which would force a new allocation on every later call). Callers still get nil on error.
func sliceValue[T scalarProtoFieldGoType](fd *FieldData, wt csproto.WireType, pick func(*fieldDataBuffers) *[]T, convertFn func([]byte) (T, int, error)) ([]T, error) {
	switch fd.wireType() {
	// wt is the wire type for values of type T
	// packed repeated fields are always WireTypeLengthDelimited
	case wt, csproto.WireTypeLengthDelimited:
		if !fd.hasData() {
			return nil, ErrTagNotFound
		}
		var reuse *[]T
		if b := fd.cold.buffers; b != nil {
			reuse = pick(b)
		}
		var res []T
		if reuse != nil && *reuse != nil {
			res = (*reuse)[:0]
		} else {
			res = make([]T, 0, fd.entryCount())
		}

		// Cache the buffer base address once — avoids repeated calls to
		// fd.cold.baseBuf() per entry in the processEntry closure below.
		base := fd.cold.baseBuf()

		// packed is true when the data is LengthDelimited but T's natural wire
		// type is not (a packed repeated numeric field): an entry holds zero or
		// more back-to-back values. Otherwise (unpacked varint/fixed, or a
		// LengthDelimited T such as string) each entry is exactly one value,
		// even when it is zero-length. decode rejects mixed wire types, so
		// this holds for every entry of the field.
		packed := fd.wireType() != wt

		// processEntry decodes the value(s) of type T from a single dataPtr entry.
		processEntry := func(d dataPtr) error {
			data := d.bytes(base)
			if !packed {
				v, _, err := convertFn(data)
				if err != nil {
					return err
				}
				res = append(res, v)
				return nil
			}
			for offset := 0; offset < len(data); {
				v, n, err := convertFn(data[offset:])
				if err != nil {
					return err
				}
				// Defensive: current convertFns return n >= 1 or an error
				// for non-empty input; this only guards against an infinite
				// loop if a future convertFn reports zero bytes consumed.
				if n <= 0 {
					return csproto.ErrInvalidVarintData
				}
				res = append(res, v)
				offset += n
			}
			return nil
		}

		// Process root (first/only entry), then repeated entries (second
		// occurrence onward), stopping at the first conversion error.
		err := processEntry(fd.root)
		for i, rep := 0, fd.cold.repeated; err == nil && i < len(rep); i++ {
			err = processEntry(rep[i])
		}

		// Store even on error: this keeps the backing array (and any growth)
		// for the next call, and keeps len covering every element written so
		// releaseAliases clears all aliased strings.
		if reuse != nil {
			fd.noteCap(cap(res))
			*reuse = res
		}
		if err != nil {
			return nil, err
		}
		return res, nil
	default:
		if wt != csproto.WireTypeLengthDelimited {
			return nil, wireTypeMismatchError(fd.wireType(), csproto.WireTypeLengthDelimited, wt)
		}
		return nil, wireTypeMismatchError(fd.wireType(), csproto.WireTypeLengthDelimited)
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
	c := cap(fd.cold.repeated)
	if b := fd.cold.buffers; b != nil {
		c = max(c, b.maxCap)
	}
	return c
}
