package csproto_test

import (
	"errors"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CrowdStrike/csproto"
)

func TestDecodeBool(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected bool
	}{
		{
			name:     "true value",
			fieldNum: 1,
			v:        []byte{0x8, 0x1},
			wt:       csproto.WireTypeVarint,
			expected: true,
		},
		{
			name:     "false value",
			fieldNum: 2,
			v:        []byte{0x10, 0x0},
			wt:       csproto.WireTypeVarint,
			expected: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeBool()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeString(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected string
	}{
		{
			name:     "empty string",
			fieldNum: 1,
			v:        []byte{0xA, 0x0},
			wt:       csproto.WireTypeLengthDelimited,
			expected: "",
		},
		{
			name:     "non-empty string",
			fieldNum: 2,
			v:        []byte{0x12, 0xE, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74},
			wt:       csproto.WireTypeLengthDelimited,
			expected: "this is a test",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeString()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeBytes(t *testing.T) {
	cases := []struct {
		name        string
		fieldNum    int
		v           []byte
		wt          csproto.WireType
		expected    []byte
		expectedErr error
	}{
		{
			name:     "empty slice",
			fieldNum: 1,
			v:        []byte{0xA, 0x0},
			wt:       csproto.WireTypeLengthDelimited,
			expected: []byte{},
		},
		{
			name:     "non-empty slice",
			fieldNum: 2,
			v:        []byte{0x12, 0x3, 0x42, 0x11, 0x38},
			wt:       csproto.WireTypeLengthDelimited,
			expected: []byte{0x42, 0x11, 0x38},
		},
		{
			name:        "invalid data",
			fieldNum:    2,
			v:           []byte{0x12, 0x3, 0x42, 0x11}, // field data is truncated
			wt:          csproto.WireTypeLengthDelimited,
			expected:    []byte{0x42, 0x11, 0x38},
			expectedErr: io.ErrUnexpectedEOF,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeBytes()
			if tc.expectedErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, got)
			} else {
				assert.ErrorIs(t, err, tc.expectedErr)
			}
		})
	}
}

func TestDecodeUInt32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected uint32
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x8, 0x0},
			wt:       csproto.WireTypeVarint,
			expected: 0,
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
			wt:       csproto.WireTypeVarint,
			expected: math.MaxUint32,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x18, 0x2A},
			wt:       csproto.WireTypeVarint,
			expected: 42,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeUInt32()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeUInt64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected uint64
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x8, 0x0},
			wt:       csproto.WireTypeVarint,
			expected: 0,
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1},
			wt:       csproto.WireTypeVarint,
			expected: math.MaxUint64,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x18, 0x92, 0xDA, 0x19},
			wt:       csproto.WireTypeVarint,
			expected: 421138,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeUInt64()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeSInt32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected int32
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x8, 0x0},
			wt:       csproto.WireTypeVarint,
			expected: 0,
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        []byte{0x10, 0xFE, 0xFF, 0xFF, 0xFF, 0x0F},
			wt:       csproto.WireTypeVarint,
			expected: math.MaxInt32,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x18, 0x54},
			wt:       csproto.WireTypeVarint,
			expected: 42,
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        []byte{0x20, 0x53},
			wt:       csproto.WireTypeVarint,
			expected: -42,
		},
		{
			name:     "min uint",
			fieldNum: 5,
			v:        []byte{0x28, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
			wt:       csproto.WireTypeVarint,
			expected: math.MinInt32,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeSInt32()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeSInt64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected int64
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x8, 0x0},
			wt:       csproto.WireTypeVarint,
			expected: 0,
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        []byte{0x10, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01},
			wt:       csproto.WireTypeVarint,
			expected: math.MaxInt64,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x18, 0xA4, 0xB4, 0x33},
			wt:       csproto.WireTypeVarint,
			expected: 421138,
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        []byte{0x20, 0xA3, 0xB4, 0x33},
			wt:       csproto.WireTypeVarint,
			expected: -421138,
		},
		{
			name:     "min uint",
			fieldNum: 4,
			v:        []byte{0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01},
			wt:       csproto.WireTypeVarint,
			expected: math.MinInt64,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeSInt64()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeFixed32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected uint32
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x0D, 0x00, 0x00, 0x00, 0x00},
			wt:       csproto.WireTypeFixed32,
			expected: 0,
		},
		{
			name:     "max int",
			fieldNum: 2,
			v:        []byte{0x15, 0xFF, 0xFF, 0xFF, 0x7F},
			wt:       csproto.WireTypeFixed32,
			expected: math.MaxInt32,
		},
		{
			name:     "max uint",
			fieldNum: 3,
			v:        []byte{0x1D, 0xFF, 0xFF, 0xFF, 0xFF},
			wt:       csproto.WireTypeFixed32,
			expected: math.MaxUint32,
		},
		{
			name:     "regular value",
			fieldNum: 4,
			v:        []byte{0x25, 0x72, 0x04, 0x00, 0x00},
			wt:       csproto.WireTypeFixed32,
			expected: 1138,
		},
		{
			name:     "\"negative\" value",
			fieldNum: 5,
			v:        []byte{0x2D, 0x72, 0x04, 0x00, 0x80},
			wt:       csproto.WireTypeFixed32,
			expected: 0x80000472, // -1138 in hex
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeFixed32()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeFixed64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected uint64
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wt:       csproto.WireTypeFixed64,
			expected: 0,
		},
		{
			name:     "max int",
			fieldNum: 2,
			v:        []byte{0x11, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
			wt:       csproto.WireTypeFixed64,
			expected: math.MaxInt64,
		},
		{
			name:     "max uint",
			fieldNum: 3,
			v:        []byte{0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wt:       csproto.WireTypeFixed64,
			expected: math.MaxUint64,
		},
		{
			name:     "regular value",
			fieldNum: 4,
			v:        []byte{0x21, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wt:       csproto.WireTypeFixed64,
			expected: 1138,
		},
		{
			name:     "\"negative\" value",
			fieldNum: 5,
			v:        []byte{0x29, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
			wt:       csproto.WireTypeFixed64,
			expected: 0x8000000000000472, // -1138 in hex
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeFixed64()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeFloat32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected float32
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x0D, 0x00, 0x00, 0x00, 0x00},
			wt:       csproto.WireTypeFixed32,
			expected: 0.0,
		},
		{
			name:     "max float",
			fieldNum: 2,
			v:        []byte{0x15, 0xFF, 0xFF, 0x7F, 0x7F},
			wt:       csproto.WireTypeFixed32,
			expected: math.MaxFloat32,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x1D, 0x88, 0x74, 0x28, 0x42},
			wt:       csproto.WireTypeFixed32,
			expected: 42.1138,
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        []byte{0x25, 0x88, 0x74, 0x28, 0xC2},
			wt:       csproto.WireTypeFixed32,
			expected: -42.1138,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeFloat32()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodeFloat64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		wt       csproto.WireType
		expected float64
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wt:       csproto.WireTypeFixed64,
			expected: 0.0,
		},
		{
			name:     "max double",
			fieldNum: 2,
			v:        []byte{0x11, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F},
			wt:       csproto.WireTypeFixed64,
			expected: math.MaxFloat64,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x19, 0x74, 0x24, 0x97, 0xFF, 0x90, 0x0E, 0x45, 0x40},
			wt:       csproto.WireTypeFixed64,
			expected: 42.1138,
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        []byte{0x21, 0x74, 0x24, 0x97, 0xFF, 0x90, 0x0e, 0x45, 0xC0},
			wt:       csproto.WireTypeFixed64,
			expected: -42.1138,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeFloat64()
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDecodePackedBool(t *testing.T) {
	var (
		data = []byte{
			// tag=4, wire type=2
			0x22,
			// total length (3)
			0x03,
			// varint true/1
			0x01,
			// varint false/0
			0x00,
			// varint true/1
			0x01,
		}
	)
	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 4, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedBool()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []bool{true, false, true}, "slice values should match")
}

func TestDecodePackedInt32(t *testing.T) {
	var (
		data = []byte{
			// tag=4, wire type=2
			0x22,
			// total length (6)
			0x06,
			// varint 3
			0x03,
			// varint 270
			0x8E, 0x02,
			// varint 86942
			0x9E, 0xA7, 0x05,
		}
	)
	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 4, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedInt32()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []int32{3, 270, 86942}, "slice values should match")
}

func TestDecodePackedInt64(t *testing.T) {
	var (
		data = []byte{
			// tag=4, wire type=2
			0x22,
			// total length (9)
			0x09,
			// varint 3
			0x03,
			// varint 270
			0x8E, 0x02,
			// varint 86942
			0x9E, 0xA7, 0x05,
			// varint 421138
			0x92, 0xDA, 0x19,
		}
	)
	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 4, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedInt64()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []int64{3, 270, 86942, 421138}, "slice values should match")
}

func TestDecodePackedUint32(t *testing.T) {
	var (
		data = []byte{
			// tag=4, wire type=2
			0x22,
			// total length (6)
			0x06,
			// varint 3
			0x03,
			// varint 270
			0x8E, 0x02,
			// varint 86942
			0x9E, 0xA7, 0x05,
		}
	)
	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 4, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedUint32()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []uint32{3, 270, 86942}, "slice values should match")
}

func TestDecodePackedUint64(t *testing.T) {
	var (
		data = []byte{
			// tag=4, wire type=2
			0x22,
			// total length (9)
			0x09,
			// varint 3
			0x03,
			// varint 270
			0x8E, 0x02,
			// varint 86942
			0x9E, 0xA7, 0x05,
			// varint 421138
			0x92, 0xDA, 0x19,
		}
	)
	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 4, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedUint64()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []uint64{3, 270, 86942, 421138}, "slice values should match")
}

func TestDecodePackedSint32(t *testing.T) {
	var (
		data = []byte{
			// tag=1, wire type=1
			0x0A,
			// total bytes (11)
			0x0B,
			// zigzag 421138
			0xA4, 0xB4, 0x33,
			// zigzag -421138
			0xA3, 0xB4, 0x33,
			// zigzag math.MaxInt32
			0xFE, 0xFF, 0xFF, 0xFF, 0x0F,
		}
	)

	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 1, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedSint32()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []int32{421138, -421138, math.MaxInt32}, "slice values should match")
}

func TestDecodePackedSint64(t *testing.T) {
	var (
		data = []byte{
			// tag=1, wire type=1
			0x0A,
			// total bytes (16)
			0x10,
			// zigzag 421138
			0xA4, 0xB4, 0x33,
			// zigzag -421138
			0xA3, 0xB4, 0x33,
			// zigzag math.MaxInt64
			0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		}
	)

	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 1, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedSint64()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []int64{421138, -421138, math.MaxInt64}, "slice values should match")
}

func TestDecodePackedFixed32(t *testing.T) {
	var (
		data = []byte{
			// tag=1, wire type=1
			0x0A,
			// total bytes (12)
			0x0C,
			// 1138
			0x72, 0x04, 0x00, 0x00,
			// -1138
			0x72, 0x04, 0x00, 0x80,
			// math.MaxUint32
			0xFF, 0xFF, 0xFF, 0xFF,
		}
	)

	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 1, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedFixed32()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []uint32{1138, 0x80000472, math.MaxUint32}, "slice values should match")
}

func TestDecodePackedFixed64(t *testing.T) {
	var (
		data = []byte{
			// tag=1, wire type=1
			0x0A,
			// total bytes (24)
			0x18,
			// 1138
			0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// -1138
			0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
			// math.MaxUint64
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}
	)

	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 1, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedFixed64()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []uint64{1138, 0x8000000000000472, math.MaxUint64}, "slice values should match")
}

func TestDecodePackedFloat32(t *testing.T) {
	var (
		data = []byte{
			// tag=1, wire type=1
			0x0A,
			// total bytes (12)
			0x0C,
			// 42.1138
			0x88, 0x74, 0x28, 0x42,
			// -42.1138
			0x88, 0x74, 0x28, 0xC2,
			// math.MaxFloat32
			0xFF, 0xFF, 0x7F, 0x7F,
		}
	)

	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 1, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedFloat32()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []float32{42.1138, -42.1138, math.MaxFloat32}, "slice values should match")
}

func TestDecodePackedFloat64(t *testing.T) {
	var (
		data = []byte{
			// tag=1, wire type=1
			0x0A,
			// total bytes (24)
			0x18,
			// 42.1138
			0x74, 0x24, 0x97, 0xFF, 0x90, 0x0E, 0x45, 0x40,
			// -42.1138
			0x74, 0x24, 0x97, 0xFF, 0x90, 0x0e, 0x45, 0xC0,
			// math.MaxFloat64
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F,
		}
	)

	dec := csproto.NewDecoder(data)
	tag, wt, err := dec.DecodeTag()
	assert.NoError(t, err)
	assert.Equal(t, 1, tag, "tag should match")
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt, "wire type should match")

	vals, err := dec.DecodePackedFloat64()
	assert.NoError(t, err)
	assert.ElementsMatch(t, vals, []float64{42.1138, -42.1138, math.MaxFloat64}, "slice values should match")
}

func TestDecoderSkip(t *testing.T) {
	var (
		data = []byte{
			// 1 (varint) - true
			0x8, 0x1,
			// 2 (varint): 42
			0x10, 0x2A,
			// 3 (fixed64): 1138
			0x19, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// 4 (length-delimited): "this is a test"
			0x22, 0xE, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74,
			// 5 (fixed32): 1138
			0x2d, 0x72, 0x04, 0x00, 0x00,
			// 6 (varint): false
			0x30, 0x0,
		}
		// byte offsets for the start of each encoded field
		fieldOffsets = []int{0, 2, 4, 13, 29, 34}
	)

	dec := csproto.NewDecoder(data)
	for i := 0; i < 6; i++ {
		tag, wt, _ := dec.DecodeTag()
		switch tag {
		case 1:
			_, _ = dec.DecodeBool()
		case 2, 3, 4, 5:
			fs, fe := fieldOffsets[i], fieldOffsets[i+1]
			skipped, err := dec.Skip(tag, wt)
			assert.NoError(t, err, "Unexpected error skipping field (%d, %s): %v", tag, wt)
			assert.Len(t, skipped, (fe - fs), "Unexpected length of skipped data for field (%d, %s)", tag, wt)
			assert.Equal(t, data[fs:fe], skipped, "Unexpected skipped content for field (%d, %s)", tag, wt)
		case 6:
			_, _ = dec.DecodeBool()
		}
	}
}

func TestDecoderInvalidSkip(t *testing.T) {
	var data = []byte{
		// 1 (varint): 42
		0x8, 0x2A,
	}
	var skipErr *csproto.DecoderSkipError

	dec := csproto.NewDecoder(data)
	// skip with incorrect tag
	_, err := dec.Skip(2, csproto.WireTypeVarint)
	assert.ErrorAs(t, err, &skipErr)
	// skip with incorrect wire types
	for _, wt := range []csproto.WireType{csproto.WireTypeFixed64, csproto.WireTypeLengthDelimited, csproto.WireTypeFixed32} {
		_, err := dec.Skip(1, wt)
		assert.ErrorAs(t, err, &skipErr)
	}
}

func TestDecodePastEndOfBuffer(t *testing.T) {
	var data = []byte{
		// 1 (varint): 42
		0x8, 0x2A,
	}

	dec := csproto.NewDecoder(data)
	// consume tag and value
	_, _, _ = dec.DecodeTag()
	_, _ = dec.DecodeInt32()
	// call each Decode* method again
	_, _, err := dec.DecodeTag()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeTag() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeBool()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeBool() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeString()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeString() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeBytes()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeBytes() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeUInt32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeUInt32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeUInt64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeUInt64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeInt32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeInt32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeInt64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeInt64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeSInt32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeSInt32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeSInt64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeSInt64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeFixed32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeFixed32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeFixed64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeFixed64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeFloat32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeFloat32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodeFloat64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeFloat64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedBool()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedBool() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedUint32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedUint32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedUint64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedUint64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedInt32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedInt32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedInt64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedInt64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedSint32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedSint32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedSint64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedSint64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedFixed32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedFixed32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedFixed64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedFixed64() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedFloat32()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedFloat32() should return io.ErrUnexpectedEOF")
	_, err = dec.DecodePackedFloat64()
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodePackedFloat64() should return io.ErrUnexpectedEOF")
	var mm interface{}
	err = dec.DecodeNested(mm)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "DecodeNested() should return io.ErrUnexpectedEOF")

	_, err = dec.Skip(1, csproto.WireTypeVarint)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "Skip() should return io.ErrUnexpectedEOF")
}

func TestDecodeTag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data []byte
		tag  int
		wt   csproto.WireType
		err  error
	}{
		{
			name: "multi-byte varint data with remaining bytes missing",
			data: []byte{0x80},
			err:  io.ErrUnexpectedEOF,
		},
		{
			name: "varint overflow",
			// 11 bytes == overflow
			data: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80},
			err:  csproto.ErrValueOverflow,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dec := csproto.NewDecoder(tc.data)

			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.tag, tag)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.Equal(t, -1, int(wt), "returned wire type should be -1 when an error occurs")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wt, wt)
			}
		})
	}
}

func FuzzDecodeTag(f *testing.F) {
	seedData := [][]byte{
		{(1 << 3)},     // tag=1, wire type=0
		{(2 << 3)},     // tag=2, wire type=0
		{(1 << 3) | 1}, // tag=1, wire type=fixed64
		{(2 << 3) | 1}, // tag=2, wire type=fixed64
		{(1 << 3) | 2}, // tag=1, wire type=length-delmited
		{(2 << 3) | 2}, // tag=2, wire type=length-delmited
		{(1 << 3) | 5}, // tag=1, wire type=fixed32
		{(2 << 3) | 5}, // tag=2, wire type=fixed32
	}
	// add seed data with max tag for each wire type
	for _, v := range []int{0, 1, 2, 5} {
		d := make([]byte, csproto.SizeOfTagKey(csproto.MaxTagValue))
		csproto.EncodeTag(d, csproto.MaxTagValue, csproto.WireType(v))
		seedData = append(seedData, d)
	}
	for _, s := range seedData {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, d []byte) {
		dec := csproto.NewDecoder(d)
		_, _, err := dec.DecodeTag()
		if err != nil {
			switch {
			case errors.Is(err, io.ErrUnexpectedEOF):
				// valid error
			case errors.Is(err, csproto.ErrValueOverflow):
				// valid error
			case errors.Is(err, csproto.ErrInvalidVarintData):
				// valid error
			default:
				t.Errorf("unexpected error from DecodeTag(): %v", err)
			}
		}
	})
}
