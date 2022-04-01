package csproto_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CrowdStrike/csproto"
)

func TestEncodeBool(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        bool
		expected []byte
	}{
		{
			name:     "true value",
			fieldNum: 1,
			v:        true,
			expected: []byte{0x8, 0x1},
		},
		{
			name:     "false value",
			fieldNum: 2,
			v:        false,
			expected: []byte{0x10, 0x0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeBool(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedBool(t *testing.T) {
	dest := make([]byte, 5)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedBool(1, []bool{true, false, true})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (3)
		0x03,
		// true, false, true
		0x01, 0x00, 0x01,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeString(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        string
		expected []byte
	}{
		{
			name:     "empty string",
			fieldNum: 1,
			v:        "",
			expected: []byte{0xA, 0x0},
		},
		{
			name:     "non-empty string",
			fieldNum: 2,
			v:        "this is a test",
			expected: []byte{0x12, 0xE, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeString(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodeBytes(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        []byte
		expected []byte
	}{
		{
			name:     "empty slice",
			fieldNum: 1,
			v:        []byte{},
			expected: []byte{0xA, 0x0},
		},
		{
			name:     "non-empty slice",
			fieldNum: 2,
			v:        []byte{0x42, 0x11, 0x38},
			expected: []byte{0x12, 0x3, 0x42, 0x11, 0x38},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeBytes(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodeInt32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        int32
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x8, 0x0},
		},
		{
			name:     "max int",
			fieldNum: 2,
			v:        math.MaxInt32,
			expected: []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x07},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        42,
			expected: []byte{0x18, 0x2A},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeInt32(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedInt32(t *testing.T) {
	dest := make([]byte, 9)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedInt32(1, []int32{0, math.MaxInt32, 42})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (7)
		0x07,
		// 0,
		0x00,
		// math.MaxInt32
		0xFF, 0xFF, 0xFF, 0xFF, 0x07,
		// 42
		0x2A,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeInt64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        int64
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x8, 0x0},
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        math.MaxInt64,
			expected: []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        421138,
			expected: []byte{0x18, 0x92, 0xDA, 0x19},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeInt64(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedInt64(t *testing.T) {
	dest := make([]byte, 15)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedInt64(1, []int64{0, math.MaxInt64, 421138})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (13)
		0x0D,
		// 0,
		0x00,
		// math.MaxInt64
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
		// 421138
		0x92, 0xDA, 0x19,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeUInt32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        uint32
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x8, 0x0},
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        math.MaxUint32,
			expected: []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        42,
			expected: []byte{0x18, 0x2A},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeUInt32(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedUInt32(t *testing.T) {
	dest := make([]byte, 9)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedUInt32(1, []uint32{0, math.MaxUint32, 42})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (7)
		0x07,
		// 0,
		0x00,
		// math.MaxUint32
		0xFF, 0xFF, 0xFF, 0xFF, 0x0F,
		// 42
		0x2A,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeUInt64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        uint64
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x8, 0x0},
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        math.MaxUint64,
			expected: []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        421138,
			expected: []byte{0x18, 0x92, 0xDA, 0x19},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeUInt64(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedUInt64(t *testing.T) {
	dest := make([]byte, 16)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedUInt64(1, []uint64{0, math.MaxUint64, 421138})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (14)
		0x0E,
		// 0,
		0x00,
		// math.MaxUint64
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1,
		// 421138
		0x92, 0xDA, 0x19,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeSInt32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        int32
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x8, 0x0},
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        math.MaxInt32,
			expected: []byte{0x10, 0xFE, 0xFF, 0xFF, 0xFF, 0x0F},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        42,
			expected: []byte{0x18, 0x54},
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        -42,
			expected: []byte{0x20, 0x53},
		},
		{
			name:     "min uint",
			fieldNum: 5,
			v:        math.MinInt32,
			expected: []byte{0x28, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeSInt32(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedSInt32(t *testing.T) {
	dest := make([]byte, 10)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedSInt32(1, []int32{0, math.MaxInt32, 42, -42})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (8)
		0x08,
		// 0,
		0x00,
		// math.MaxUint32
		0xFE, 0xFF, 0xFF, 0xFF, 0x0F,
		// 42
		0x54,
		// -42
		0x53,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeSInt64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        int64
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x8, 0x0},
		},
		{
			name:     "max uint",
			fieldNum: 2,
			v:        math.MaxInt64,
			expected: []byte{0x10, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        421138,
			expected: []byte{0x18, 0xA4, 0xB4, 0x33},
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        -421138,
			expected: []byte{0x20, 0xA3, 0xB4, 0x33},
		},
		{
			name:     "min uint",
			fieldNum: 4,
			v:        math.MinInt64,
			expected: []byte{0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeSInt64(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedSInt64(t *testing.T) {
	dest := make([]byte, 19)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedSInt64(1, []int64{0, math.MaxInt64, 421138, -421138})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (17)
		0x11,
		// 0,
		0x00,
		// math.MaxInt64
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		// 421138
		0xA4, 0xB4, 0x33,
		// -421138
		0xA3, 0xB4, 0x33,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeFixed32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        uint32
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x0D, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "max int",
			fieldNum: 2,
			v:        math.MaxInt32,
			expected: []byte{0x15, 0xFF, 0xFF, 0xFF, 0x7F},
		},
		{
			name:     "max uint",
			fieldNum: 3,
			v:        math.MaxUint32,
			expected: []byte{0x1D, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:     "regular value",
			fieldNum: 4,
			v:        1138,
			expected: []byte{0x25, 0x72, 0x04, 0x00, 0x00},
		},
		{
			name:     "\"negative\" value",
			fieldNum: 5,
			v:        0x80000472, // -1138 in hex
			expected: []byte{0x2D, 0x72, 0x04, 0x00, 0x80},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeFixed32(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedFixed32(t *testing.T) {
	dest := make([]byte, 14)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedFixed32(1, []uint32{0, math.MaxUint32, 1138})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (12)
		0x0c,
		// 0,
		0x00, 0x00, 0x00, 0x00,
		// math.MaxUint32
		0xFF, 0xFF, 0xFF, 0xFF,
		// 1138
		0x72, 0x04, 0x00, 0x00,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeFixed64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        uint64
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0,
			expected: []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "max int",
			fieldNum: 2,
			v:        math.MaxInt64,
			expected: []byte{0x11, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
		},
		{
			name:     "max uint",
			fieldNum: 3,
			v:        math.MaxUint64,
			expected: []byte{0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:     "regular value",
			fieldNum: 4,
			v:        1138,
			expected: []byte{0x21, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "\"negative\" value",
			fieldNum: 5,
			v:        0x8000000000000472, // -1138 in hex
			expected: []byte{0x29, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeFixed64(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedFixed64(t *testing.T) {
	dest := make([]byte, 26)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedFixed64(1, []uint64{0, math.MaxUint64, 1138})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (24)
		0x18,
		// 0,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// math.MaxUint64
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		// 1138
		0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeFloat32(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        float32
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0.0,
			expected: []byte{0x0D, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "max float",
			fieldNum: 2,
			v:        math.MaxFloat32,
			expected: []byte{0x15, 0xFF, 0xFF, 0x7F, 0x7F},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        42.1138,
			expected: []byte{0x1D, 0x88, 0x74, 0x28, 0x42},
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        -42.1138,
			expected: []byte{0x25, 0x88, 0x74, 0x28, 0xC2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeFloat32(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedFloat32(t *testing.T) {
	dest := make([]byte, 18)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedFloat32(1, []float32{0, math.MaxFloat32, 42.1138, -42.1138})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (16)
		0x10,
		// 0,
		0x00, 0x00, 0x00, 0x00,
		// math.MaxFloat32
		0xFF, 0xFF, 0x7F, 0x7F,
		// 42.1138
		0x88, 0x74, 0x28, 0x42,
		// -42.1138
		0x88, 0x74, 0x28, 0xC2,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeFloat64(t *testing.T) {
	cases := []struct {
		name     string
		fieldNum int
		v        float64
		expected []byte
	}{
		{
			name:     "zero",
			fieldNum: 1,
			v:        0.0,
			expected: []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "max double",
			fieldNum: 2,
			v:        math.MaxFloat64,
			expected: []byte{0x11, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F},
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        42.1138,
			expected: []byte{0x19, 0x74, 0x24, 0x97, 0xFF, 0x90, 0x0E, 0x45, 0x40},
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        -42.1138,
			expected: []byte{0x21, 0x74, 0x24, 0x97, 0xFF, 0x90, 0x0e, 0x45, 0xC0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, len(tc.expected))
			csproto.NewEncoder(dest).EncodeFloat64(tc.fieldNum, tc.v)
			assert.Equal(t, tc.expected, dest)
		})
	}
}

func TestEncodePackedFloat64(t *testing.T) {
	dest := make([]byte, 34)
	enc := csproto.NewEncoder(dest)
	enc.EncodePackedFloat64(1, []float64{0, math.MaxFloat64, 42.1138, -42.1138})

	expected := []byte{
		// tag=1, wire type=2
		0x0a,
		// total length (32)
		0x20,
		// 0,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// math.MaxFloat64
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F,
		// 42.1138
		0x74, 0x24, 0x97, 0xFF, 0x90, 0x0E, 0x45, 0x40,
		// -42.1138
		0x74, 0x24, 0x97, 0xFF, 0x90, 0x0e, 0x45, 0xC0,
	}
	assert.Equal(t, expected, dest)
}

func TestEncodeNested(t *testing.T) {
	var (
		name           = "test"
		val      int32 = 42
		expected       = []byte{0xa, 0x8, 0xa, 0x4, 0x74, 0x65, 0x73, 0x74, 0x10, 0x2a}
	)
	m := testNestedMsg{
		Name:  &name,
		Value: &val,
	}

	sz := m.Size()
	buf := make([]byte, 1+csproto.SizeOfVarint(uint64(sz))+sz)
	enc := csproto.NewEncoder(buf)

	err := enc.EncodeNested(1, &m)

	assert.NoError(t, err)
	assert.Equal(t, expected, buf)
}

func TestEncodeRaw(t *testing.T) {
	var (
		data = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		buf  = make([]byte, 8)
	)

	enc := csproto.NewEncoder(buf)

	enc.EncodeRaw(data)

	assert.Equal(t, data, buf)
}

type testNestedMsg struct {
	Name  *string
	Value *int32
}

func (m *testNestedMsg) Size() int {
	var (
		sz = 0
		l  int
	)
	if m.Name != nil {
		l = len(*m.Name)
		sz += 1 + csproto.SizeOfVarint(uint64(l)) + l
	}
	if m.Value != nil {
		sz += 1 + csproto.SizeOfVarint(uint64(*m.Value))
	}
	return sz
}

func (m *testNestedMsg) MarshalTo(dest []byte) error {
	enc := csproto.NewEncoder(dest)
	if m.Name != nil {
		enc.EncodeString(1, *m.Name)
	}
	if m.Value != nil {
		enc.EncodeInt32(2, *m.Value)
	}
	return nil
}
