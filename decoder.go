package csproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unsafe"
)

var (
	// ErrInvalidFieldTag is returned by the decoder when it fails to read a varint-encoded field tag/wire type value.
	ErrInvalidFieldTag = errors.New("unable to read protobuf field tag")
	// ErrInvalidVarintData is returned by the decoder when it fails to read a varint-encoded value.
	ErrInvalidVarintData = errors.New("unable to read protobuf varint value")
	// ErrValueOverflow is returned by DecodeUInt32() or DecodeInt32() when the decoded value is too large for a 32-bit value.
	ErrValueOverflow = errors.New("value overflow trying to read protobuf varint value")
	// ErrInvalidZigZagData is returned by the decoder when it fails to read a zigzag-encoded value.
	ErrInvalidZigZagData = errors.New("unable to read protobuf zigzag value")
	// ErrInvalidFixed32Data is returned by the decoder when it fails to read a fixed-size 32-bit value.
	ErrInvalidFixed32Data = errors.New("unable to read protobuf fixed 32-bit value")
	// ErrInvalidFixed64Data is returned by the decoder when it fails to read a fixed-size 64-bit value.
	ErrInvalidFixed64Data = errors.New("unable to read protobuf fixed 64-bit value")
	// ErrInvalidPackedData is returned by the decoder when it fails to read a packed repeated value.
	ErrInvalidPackedData = errors.New("unable to read protobuf packed value")
)

// DecoderMode defines the behavior of the decoder (safe vs fastest).
type DecoderMode int

const (
	// DecoderModeSafe instructs the decoder to only use safe operations when decoding values.
	DecoderModeSafe DecoderMode = iota
	// DecoderModeFast instructs the decoder to use unsafe operations to avoid allocations and copying data
	// for the fastest throughput.
	//
	// When using DecoderModeFast, the byte slice passed to the decoder must not be modified after
	// using the decoder to extract values.  The behavior is undefined if the slice is modified.
	DecoderModeFast
)

// String returns a string representation of m, "safe" or "fast".
func (m DecoderMode) String() string {
	if m == DecoderModeSafe {
		return "safe"
	}
	return "fast"
}

// Decoder implements a binary Protobuf Decoder by sequentially reading from a provided []byte.
type Decoder struct {
	p      []byte
	offset int
	mode   DecoderMode
}

// NewDecoder initializes a new Protobuf decoder to read the provided buffer.
func NewDecoder(p []byte) *Decoder {
	return &Decoder{
		p:      p,
		offset: 0,
	}
}

// SetMode configures the decoding behavior, safe vs fastest.
func (d *Decoder) SetMode(m DecoderMode) {
	d.mode = m
}

// Reset moves the read offset back to the beginning of the encoded data
func (d *Decoder) Reset() {
	d.offset = 0
}

// More indicates if there is more data to be read in the buffer.
func (d *Decoder) More() bool {
	return d.offset < len(d.p)
}

// DecodeTag decodes a field tag and Protobuf wire type from the stream and returns the values.
func (d *Decoder) DecodeTag() (tag int, wireType WireType, err error) {
	v, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return 0, -1, ErrInvalidFieldTag
	}
	d.offset += n
	return int(v >> 3), WireType(v & 0x7), nil
}

// DecodeBool decodes a boolean value from the stream and returns the value.
func (d *Decoder) DecodeBool() (b bool, err error) {
	v, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return false, ErrInvalidVarintData
	}
	d.offset += n
	return (v != 0), nil
}

// DecodeString decodes a length-delimited string from the stream and returns the value.
func (d *Decoder) DecodeString() (string, error) {
	b, err := d.DecodeBytes()
	if err != nil {
		return "", err
	}
	switch d.mode {
	case DecoderModeFast:
		return *(*string)(unsafe.Pointer(&b)), nil //nolint: gosec // using unsafe on purpose

	default:
		// safe mode by default
		return string(b), nil
	}
}

// DecodeBytes decodes a length-delimited slice of bytes from the stream and returns the value.
func (d *Decoder) DecodeBytes() ([]byte, error) {
	l, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	b := d.p[d.offset+n : d.offset+n+int(l)]
	d.offset += n + int(l)
	return b, nil
}

// DecodeUInt32 decodes a varint-encoded 32-bit unsigned integer from the stream and returns the value.
func (d *Decoder) DecodeUInt32() (uint32, error) {
	v, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidVarintData
	}
	if v > math.MaxUint32 {
		return 0, ErrValueOverflow
	}
	d.offset += n
	return uint32(v), nil
}

// DecodeUInt64 decodes a varint-encoded 64-bit unsigned integer from the stream and returns the value.
func (d *Decoder) DecodeUInt64() (uint64, error) {
	v, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidVarintData
	}
	d.offset += n
	return v, nil
}

// DecodeInt32 decodes a varint-encoded 32-bit integer from the stream and returns the value.
func (d *Decoder) DecodeInt32() (int32, error) {
	v, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidVarintData
	}
	if v > math.MaxUint32 {
		return 0, ErrValueOverflow
	}
	d.offset += n
	return int32(v), nil
}

// DecodeInt64 decodes a varint-encoded 64-bit integer from the stream and returns the value.
func (d *Decoder) DecodeInt64() (int64, error) {
	v, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidVarintData
	}
	d.offset += n
	return int64(v), nil
}

// DecodeSInt32 decodes a zigzag-encoded 32-bit integer from the stream and returns the value.
func (d *Decoder) DecodeSInt32() (int32, error) {
	v, n := decodeZigZag32(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidZigZagData
	}
	d.offset += n
	return v, nil
}

// DecodeSInt64 decodes a zigzag-encoded 32-bit integer from the stream and returns the value.
func (d *Decoder) DecodeSInt64() (int64, error) {
	v, n := decodeZigZag64(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidZigZagData
	}
	d.offset += n
	return v, nil
}

// DecodeFixed32 decodes a 4-byte integer from the stream and returns the value.
func (d *Decoder) DecodeFixed32() (uint32, error) {
	v, n := decodeFixed32(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidFixed32Data
	}
	d.offset += n
	return v, nil
}

// DecodeFixed64 decodes an 8-byte integer from the stream and returns the value.
func (d *Decoder) DecodeFixed64() (uint64, error) {
	v, n := decodeFixed64(d.p[d.offset:])
	if n == 0 {
		return 0, ErrInvalidFixed64Data
	}
	d.offset += n
	return v, nil
}

// DecodeFloat32 decodes a 4-byte IEEE 754 floating point value from the stream and returns the value.
func (d *Decoder) DecodeFloat32() (float32, error) {
	v := binary.LittleEndian.Uint32(d.p[d.offset:])
	fv := math.Float32frombits(v)
	d.offset += 4
	return fv, nil
}

// DecodeFloat64 decodes an 8-byte IEEE 754 floating point value from the stream and returns the value.
func (d *Decoder) DecodeFloat64() (float64, error) {
	v := binary.LittleEndian.Uint64(d.p[d.offset:])
	fv := math.Float64frombits(v)
	d.offset += 8
	return fv, nil
}

// DecodePackedBool decodes a packed encoded list of boolean values from the stream and returns the value.
func (d *Decoder) DecodePackedBool() ([]bool, error) {
	var (
		l, nRead uint64
		n        int
		res      []bool
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeVarint(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, (v != 0))
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedInt32 decodes a packed encoded list of 32-bit integers from the stream and returns the value.
func (d *Decoder) DecodePackedInt32() ([]int32, error) {
	var (
		l, nRead uint64
		n        int
		res      []int32
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeVarint(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		if v > math.MaxInt32 {
			return nil, ErrValueOverflow
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, int32(v))
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedInt64 decodes a packed encoded list of 64-bit integers from the stream and returns the value.
func (d *Decoder) DecodePackedInt64() ([]int64, error) {
	var (
		l, nRead uint64
		n        int
		res      []int64
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeVarint(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		if v > math.MaxInt64 {
			return nil, ErrValueOverflow
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, int64(v))
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedUint32 decodes a packed encoded list of unsigned 32-bit integers from the stream and
// returns the value.
func (d *Decoder) DecodePackedUint32() ([]uint32, error) {
	var (
		l, nRead uint64
		n        int
		res      []uint32
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeVarint(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		if v > math.MaxUint32 {
			return nil, ErrValueOverflow
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, uint32(v))
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedUint64 decodes a packed encoded list of unsigned 64-bit integers from the stream and
// returns the value.
func (d *Decoder) DecodePackedUint64() ([]uint64, error) {
	var (
		l, nRead uint64
		n        int
		res      []uint64
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeVarint(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, v)
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedSint32 decodes a packed encoded list of 32-bit signed integers from the stream and returns
// the value.
func (d *Decoder) DecodePackedSint32() ([]int32, error) {
	var (
		l, nRead uint64
		n        int
		res      []int32
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeZigZag32(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, v)
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedSint64 decodes a packed encoded list of 64-bit signed integers from the stream and returns
// the value.
func (d *Decoder) DecodePackedSint64() ([]int64, error) {
	var (
		l, nRead uint64
		n        int
		res      []int64
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeZigZag64(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, v)
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedFixed32 decodes a packed encoded list of 32-bit fixed-width integers from the stream
// and returns the value.
func (d *Decoder) DecodePackedFixed32() ([]uint32, error) {
	var (
		l, nRead uint64
		n        int
		res      []uint32
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeFixed32(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, v)
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedFixed64 decodes a packed encoded list of 64-bit fixed-width integers from the stream
// and returns the value.
func (d *Decoder) DecodePackedFixed64() ([]uint64, error) {
	var (
		l, nRead uint64
		n        int
		res      []uint64
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v, n := decodeFixed64(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		nRead += uint64(n)
		d.offset += n
		res = append(res, v)
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedFloat32 decodes a packed encoded list of 32-bit floating point numbers from the stream
// and returns the value.
func (d *Decoder) DecodePackedFloat32() ([]float32, error) {
	var (
		l, nRead uint64
		n        int
		res      []float32
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	res = make([]float32, 0, l/4)
	for nRead < l {
		v := binary.LittleEndian.Uint32(d.p[d.offset:])
		nRead += 4
		d.offset += 4
		res = append(res, math.Float32frombits(v))
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodePackedFloat64 decodes a packed encoded list of 64-bit floating point numbers from the stream
// and returns the value.
func (d *Decoder) DecodePackedFloat64() ([]float64, error) {
	var (
		l, nRead uint64
		n        int
		res      []float64
	)
	l, n = decodeVarint(d.p[d.offset:])
	if n == 0 {
		return nil, ErrInvalidVarintData
	}
	d.offset += n
	for nRead < l {
		v := binary.LittleEndian.Uint64(d.p[d.offset:])
		nRead += 8
		d.offset += 8
		res = append(res, math.Float64frombits(v))
	}
	if nRead != l {
		return nil, ErrInvalidPackedData
	}
	return res, nil
}

// DecodeNested decodes a nested Protobuf message from the stream into m.  If m satisfies our csproto.Unmarshaler
// interface its Unmarshal() method will be called.  Otherwise, this method delegates to Marshal().
func (d *Decoder) DecodeNested(m interface{}) error {
	l, n := decodeVarint(d.p[d.offset:])
	if n == 0 {
		return ErrInvalidVarintData
	}
	if l == 0 {
		d.offset += n
		return nil
	}
	switch tv := m.(type) {
	case Unmarshaler:
		if err := tv.Unmarshal(d.p[d.offset+n : d.offset+n+int(l)]); err != nil {
			return err
		}
	default:
		if err := Unmarshal(d.p[d.offset+n:d.offset+n+int(l)], m); err != nil {
			return err
		}
	}
	d.offset += n + int(l)
	return nil
}

// Skip skips over the encoded field value at the current offset, returning the raw bytes so that the
// caller can decide what to do with the data.
//
// The tag and wire type are validated against the provided values and a DecoderSkipError error is
// returned if they do not match.  This check is skipped when using "fast" mode.
func (d *Decoder) Skip(tag int, wt WireType) ([]byte, error) {
	sz := SizeOfTagKey(tag)
	bof := d.offset - sz
	// account for skipping the first field
	if bof < 0 {
		bof = 0
	}
	// validate that the field we're skipping matches the specified tag and wire type
	// . skip validation in fast mode
	if d.mode == DecoderModeSafe {
		v, n := decodeVarint(d.p[bof:])
		if n != sz {
			return nil, ErrInvalidVarintData
		}
		if int(v>>3) != tag || WireType(v&0x7) != wt {
			return nil, &DecoderSkipError{
				ExpectedTag:      tag,
				ExpectedWireType: wt,
				ActualTag:        int(v >> 3),
				ActualWireType:   WireType(v & 0x7),
			}
		}
	}
	switch wt {
	case WireTypeVarint:
		_, n := decodeVarint(d.p[d.offset:])
		d.offset += n
	case WireTypeFixed64:
		d.offset += 8
	case WireTypeLengthDelimited:
		l, n := decodeVarint(d.p[d.offset:])
		if n == 0 {
			return nil, ErrInvalidVarintData
		}
		d.offset += n + int(l)
	case WireTypeFixed32:
		d.offset += 4
	}
	return d.p[bof:d.offset], nil
}

func decodeVarint(p []byte) (v uint64, n int) {
	for shift := uint(0); shift < 64; shift += 7 {
		if n > len(p) {
			return 0, 0
		}
		b := uint64(p[n])
		n++
		v |= (b & 0x7f << shift)
		if (b & 0x80) == 0 {
			return v, n
		}
	}
	return 0, 0
}

func decodeZigZag32(p []byte) (v int32, n int) {
	var dv uint64
	dv, n = decodeVarint(p)
	if n == 0 {
		return 0, 0
	}
	dv = uint64((uint32(dv) >> 1) ^ uint32((int32(dv&1)<<31)>>31))
	return int32(dv), n
}

func decodeZigZag64(p []byte) (v int64, n int) {
	var dv uint64
	dv, n = decodeVarint(p)
	if n == 0 {
		return 0, 0
	}
	dv = (dv >> 1) ^ uint64((int64(dv&1)<<63)>>63)
	return int64(dv), n
}

func decodeFixed32(p []byte) (v uint32, n int) {
	// we only care about the first 4 bytes, so help the compiler eliminate bounds checks
	p = p[:4]
	v = uint32(p[0])
	v |= uint32(p[1]) << 8
	v |= uint32(p[2]) << 16
	v |= uint32(p[3]) << 24
	return v, 4
}

func decodeFixed64(p []byte) (v uint64, n int) {
	// we only care about the first 8 bytes, so help the compiler eliminate bounds checks
	p = p[:8]
	v = uint64(p[0])
	v |= uint64(p[1]) << 8
	v |= uint64(p[2]) << 16
	v |= uint64(p[3]) << 24
	v |= uint64(p[4]) << 32
	v |= uint64(p[5]) << 40
	v |= uint64(p[6]) << 48
	v |= uint64(p[7]) << 56
	return v, 8
}

// DecoderSkipError defines an error returned by the decoder's Skip() method when the specified tag and
// wire type do not match the data in the stream at the current decoder offset.
type DecoderSkipError struct {
	ExpectedTag      int
	ExpectedWireType WireType
	ActualTag        int
	ActualWireType   WireType
}

// Error satisfies the error interface
func (e *DecoderSkipError) Error() string {
	return fmt.Sprintf("unexpected tag/wire type (%d, %s), expected (%d, %s)", e.ActualTag, e.ActualWireType, e.ExpectedTag, e.ExpectedWireType)
}
