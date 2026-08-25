package csproto_test

import (
	"errors"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CrowdStrike/csproto"
)

func TestDecoderSeek(t *testing.T) {
	testData := []byte{0x08, 0x01, 0x10, 0x00, 0x1A, 0xE, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74}
	dec := csproto.NewDecoder(testData)

	t.Run("seek start", func(t *testing.T) {
		t.Run("negative seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			startPos := int64(dec.Offset())
			pos, err := dec.Seek(-1, io.SeekStart)
			assert.Error(t, err, "cannot seek to before BOF")
			assert.Equal(t, startPos, pos, "read position should not change")
		})
		t.Run("zero seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			pos, err := dec.Seek(0, io.SeekStart)
			assert.NoError(t, err)
			assert.Equal(t, int64(0), pos, "new read position should be BOF")
		})
		t.Run("invalid positive seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			startPos := int64(dec.Offset())
			pos, err := dec.Seek(int64(len(testData)+1), io.SeekStart)
			assert.Error(t, err, "cannot seek to after EOF")
			assert.Equal(t, startPos, pos, "read position should not change")
		})
		t.Run("valid positive seek", func(t *testing.T) {
			dec.Reset()

			pos, err := dec.Seek(2, io.SeekStart)
			assert.NoError(t, err)
			assert.Equal(t, int(pos), dec.Offset())
			assert.True(t, dec.More())
		})
	})
	t.Run("seek current", func(t *testing.T) {
		t.Run("invalid negative seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			startPos := int64(dec.Offset())
			pos, err := dec.Seek(-1*(startPos+1), io.SeekCurrent)
			assert.Error(t, err, "cannot seek to before BOF")
			assert.Equal(t, startPos, pos, "read position should not change")
		})
		t.Run("valid negative seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			startPos := int64(dec.Offset())
			pos, err := dec.Seek(-1*startPos, io.SeekCurrent)
			assert.NoError(t, err)
			assert.Equal(t, int64(0), pos)
		})
		t.Run("zero seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			startPos := int64(dec.Offset())
			pos, err := dec.Seek(0, io.SeekCurrent)
			assert.NoError(t, err)
			assert.Equal(t, startPos, pos)
		})
		t.Run("invalid positive seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			startPos := int64(dec.Offset())
			pos, err := dec.Seek(int64(len(testData)), io.SeekCurrent)
			assert.Error(t, err, "cannot seek to after EOF")
			assert.Equal(t, startPos, pos, "read position should not change")
		})
		t.Run("valid positive seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			pos, err := dec.Seek(2, io.SeekCurrent)
			assert.NoError(t, err)
			assert.Equal(t, int(pos), dec.Offset())
			assert.True(t, dec.More())
		})
	})
	t.Run("seek end", func(t *testing.T) {
		t.Run("positive seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()
			startPos := dec.Offset()

			pos, err := dec.Seek(1, io.SeekEnd)
			assert.Error(t, err, "cannot seek to after EOF")
			assert.Equal(t, int64(startPos), pos, "read position should not change")
		})
		t.Run("zero seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			pos, err := dec.Seek(0, io.SeekEnd)
			assert.NoError(t, err)
			assert.Equal(t, int64(len(testData)), pos, "read position should be at EOF")
			assert.False(t, dec.More())
		})
		t.Run("invalid negative seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()
			startPos := dec.Offset()

			pos, err := dec.Seek(int64(-1*(len(testData)+1)), io.SeekEnd)
			assert.Error(t, err, "cannot seek to before BOF")
			assert.Equal(t, int64(startPos), pos, "read position should be at EOF")
		})
		t.Run("valid negative seek", func(t *testing.T) {
			dec.Reset()
			_, _, _ = dec.DecodeTag()
			_, _ = dec.DecodeBool()

			pos, err := dec.Seek(-16, io.SeekEnd)
			assert.NoError(t, err)
			assert.Equal(t, int64(4), pos, "read position should be at EOF")
		})
	})
	t.Run("invalid whence", func(t *testing.T) {
		dec.Reset()
		startPos := dec.Offset()
		pos, err := dec.Seek(0, 1138)
		assert.Error(t, err, "cannot seek with invalid 'whence'")
		assert.Equal(t, int64(startPos), pos, "read position should not change")
	})
}

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

	// separate t.Run() because we're not checking for sentinel errors
	t.Run("corrupt messages", func(t *testing.T) {
		t.Run("truncated data", func(t *testing.T) {
			// length-delimited field value with a length of 3 but only 2 bytes
			data := []byte{0x12, 0x3, 0x42, 0x11}
			dec := csproto.NewDecoder(data)

			got, err := dec.DecodeBytes()
			assert.Error(t, err)
			assert.Nil(t, got)
		})
		t.Run("negative length", func(t *testing.T) {
			// length-delimited field value with a length of -50
			data := []byte{0xCE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x3, 0x42, 0x11, 0x38}
			dec := csproto.NewDecoder(data)

			got, err := dec.DecodeBytes()
			assert.Error(t, err)
			assert.Nil(t, got)
		})
		t.Run("length overflow", func(t *testing.T) {
			// field length greater than 2GB
			data := []byte{0x80, 0x80, 0x80, 0x80, 0x08}
			dec := csproto.NewDecoder(data)

			got, err := dec.DecodeBytes()
			assert.Error(t, err)
			assert.Nil(t, got)
		})
	})
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

func TestDecodeInt32(t *testing.T) {
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
			name:     "max int",
			fieldNum: 2,
			v:        []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x07},
			wt:       csproto.WireTypeVarint,
			expected: math.MaxInt32,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x18, 0x2A},
			wt:       csproto.WireTypeVarint,
			expected: 42,
		},
		{
			name:     "negative value",
			fieldNum: 4,
			v:        []byte{0x20, 0xd6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1},
			wt:       csproto.WireTypeVarint,
			expected: -42,
		},
		{
			name:     "min int",
			fieldNum: 5,
			v:        []byte{0x28, 0x80, 0x80, 0x80, 0x80, 0xf8, 0xff, 0xff, 0xff, 0xff, 0x1},
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

			got, err := dec.DecodeInt32()
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

func TestDecodeInt64(t *testing.T) {
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
			name:     "max int",
			fieldNum: 2,
			v:        []byte{0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
			wt:       csproto.WireTypeVarint,
			expected: math.MaxInt64,
		},
		{
			name:     "min int",
			fieldNum: 2,
			v:        []byte{0x10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x1},
			wt:       csproto.WireTypeVarint,
			expected: math.MinInt64,
		},
		{
			name:     "regular value",
			fieldNum: 3,
			v:        []byte{0x18, 0x92, 0xDA, 0x19},
			wt:       csproto.WireTypeVarint,
			expected: 421138,
		},
		{
			name:     "negative value",
			fieldNum: 3,
			v:        []byte{0x18, 0xee, 0xa5, 0xe6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1},
			wt:       csproto.WireTypeVarint,
			expected: -421138,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := csproto.NewDecoder(tc.v)
			tag, wt, err := dec.DecodeTag()
			assert.Equal(t, tc.fieldNum, tag, "tag should match")
			assert.Equal(t, tc.wt, wt, "wire type should match")
			assert.NoError(t, err, "should not fail")

			got, err := dec.DecodeInt64()
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

	t.Run("corrupt messages", func(t *testing.T) {
		t.Run("truncated data", func(t *testing.T) {
			// length-delimited field value with a length of 3 but only 2 bytes
			data := []byte{0x0A, 0x3, 0x42, 0x11}
			dec := csproto.NewDecoder(data)

			tag, wt, _ := dec.DecodeTag()
			got, err := dec.Skip(tag, wt)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
		t.Run("negative length", func(t *testing.T) {
			// length-delimited field value with a length of -50
			data := []byte{0x0A, 0xCE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x3, 0x42, 0x11, 0x38}
			dec := csproto.NewDecoder(data)

			tag, wt, _ := dec.DecodeTag()
			got, err := dec.Skip(tag, wt)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
		t.Run("length overflow", func(t *testing.T) {
			// length-delimited field with length greater than 2GB
			data := []byte{0x0A, 0x80, 0x80, 0x80, 0x80, 0x08}
			dec := csproto.NewDecoder(data)

			tag, wt, _ := dec.DecodeTag()
			got, err := dec.Skip(tag, wt)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
	})
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

func TestDecodeVarint(t *testing.T) {
	t.Parallel()

	// Helper: encode a uint64 to varint bytes
	encode := func(v uint64) []byte {
		buf := make([]byte, 10)
		n := csproto.EncodeVarint(buf, v)
		return buf[:n]
	}

	t.Run("valid values", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name  string
			input []byte
			want  uint64
			wantN int
		}{
			// Single byte values (0x00–0x7F)
			{"zero", []byte{0x00}, 0, 1},
			{"one", []byte{0x01}, 1, 1},
			{"max_single_byte_127", []byte{0x7f}, 127, 1},
			{"single_byte_with_trailing", []byte{0x05, 0xFF, 0xFF}, 5, 1},

			// Two byte values
			{"min_2byte_128", encode(128), 128, 2},
			{"val_300", encode(300), 300, 2},
			{"max_2byte_16383", encode(16383), 16383, 2},

			// Three byte values
			{"min_3byte_16384", encode(16384), 16384, 3},
			{"val_100000", encode(100000), 100000, 3},
			{"max_3byte_2097151", encode(2097151), 2097151, 3},

			// Four byte values
			{"min_4byte_2097152", encode(2097152), 2097152, 4},
			{"max_4byte_268435455", encode(268435455), 268435455, 4},

			// Five byte values
			{"min_5byte_268435456", encode(268435456), 268435456, 5},
			{"max_uint32", encode(math.MaxUint32), math.MaxUint32, 5},
			{"max_5byte_34359738367", encode(34359738367), 34359738367, 5},

			// Six byte values
			{"min_6byte_34359738368", encode(34359738368), 34359738368, 6},
			{"max_6byte_4398046511103", encode(4398046511103), 4398046511103, 6},

			// Seven byte values
			{"min_7byte_4398046511104", encode(4398046511104), 4398046511104, 7},
			{"max_7byte_562949953421311", encode(562949953421311), 562949953421311, 7},

			// Eight byte values
			{"min_8byte_562949953421312", encode(562949953421312), 562949953421312, 8},
			{"max_8byte_72057594037927935", encode(72057594037927935), 72057594037927935, 8},

			// Nine byte values
			{"min_9byte_72057594037927936", encode(72057594037927936), 72057594037927936, 9},
			{"max_int64", encode(math.MaxInt64), math.MaxInt64, 9},

			// Ten byte values
			{"min_10byte_2^63", encode(1 << 63), 1 << 63, 10},
			{"max_uint64", encode(math.MaxUint64), math.MaxUint64, 10},
			{"negative_one_as_uint64", encode(math.MaxUint64), math.MaxUint64, 10},

			// Minimal payload patterns (0x80...0x80, 0x01)
			{"min_payload_2byte", []byte{0x80, 0x01}, 128, 2},
			{"min_payload_3byte", []byte{0x80, 0x80, 0x01}, 1 << 14, 3},
			{"min_payload_4byte", []byte{0x80, 0x80, 0x80, 0x01}, 1 << 21, 4},
			{"min_payload_5byte", []byte{0x80, 0x80, 0x80, 0x80, 0x01}, 1 << 28, 5},
			{"min_payload_6byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1 << 35, 6},
			{"min_payload_7byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1 << 42, 7},
			{"min_payload_8byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1 << 49, 8},
			{"min_payload_9byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1 << 56, 9},
			{"min_payload_10byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1 << 63, 10},

			// Max payload patterns (0xFF...0xFF, 0x7F)
			{"max_payload_2byte", []byte{0xFF, 0x7F}, (1 << 14) - 1, 2},
			{"max_payload_3byte", []byte{0xFF, 0xFF, 0x7F}, (1 << 21) - 1, 3},
			{"max_payload_4byte", []byte{0xFF, 0xFF, 0xFF, 0x7F}, (1 << 28) - 1, 4},
			{"max_payload_5byte", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x7F}, (1 << 35) - 1, 5},

			// Protobuf field tags: (tag << 3 | wire_type)
			{"tag_1_varint", encode(1<<3 | 0), 1<<3 | 0, 1},
			{"tag_1_bytes", encode(1<<3 | 2), 1<<3 | 2, 1},
			{"tag_15_varint", encode(15<<3 | 0), 15<<3 | 0, 1},
			{"tag_16_varint", encode(16<<3 | 0), 16<<3 | 0, 2},
			{"tag_2047_varint", encode(2047<<3 | 0), 2047<<3 | 0, 2},
			{"tag_2048_varint", encode(2048<<3 | 0), 2048<<3 | 0, 3},
			{"tag_19000_varint", encode(19000<<3 | 0), 19000<<3 | 0, 3},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				v, n, err := csproto.DecodeVarint(tc.input)
				require.NoError(t, err)
				assert.Equal(t, tc.want, v)
				assert.Equal(t, tc.wantN, n)
			})
		}
	})

	t.Run("error cases", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			input   []byte
			wantErr error
		}{
			// Empty/nil
			{"nil_input", nil, csproto.ErrInvalidVarintData},
			{"empty_input", []byte{}, csproto.ErrInvalidVarintData},

			// Single byte with continuation bit (needs more but has none)
			{"sz1_0x80", []byte{0x80}, io.ErrUnexpectedEOF},
			{"sz1_0xFF", []byte{0xFF}, io.ErrUnexpectedEOF},
			{"sz1_0xFE", []byte{0xFE}, io.ErrUnexpectedEOF},

			// All continuation bytes, no terminator (sz 2-9)
			{"all_cont_sz2", []byte{0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz3", []byte{0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz4", []byte{0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz5", []byte{0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz6", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz7", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz8", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz9", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},

			// All continuation bytes, no terminator (sz 2-9)
			{"all_cont_sz2", []byte{0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz3", []byte{0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz4", []byte{0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz5", []byte{0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz6", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz7", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz8", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},
			{"all_cont_sz9", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, io.ErrUnexpectedEOF},

			// 10+ bytes all with continuation bit set (overflow)
			{"overflow_10byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, csproto.ErrValueOverflow},
			{"overflow_11byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, csproto.ErrValueOverflow},
			{"overflow_ff_10byte", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, csproto.ErrValueOverflow},

			// 10th byte has continuation bit set (would need an 11th byte, overflows)
			{"overflow_10th_byte_cont", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, csproto.ErrValueOverflow},
			// All payload bits set with continuation in every byte including the 10th
			{"overflow_all_ff_cont", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80}, csproto.ErrValueOverflow},
			// 10 bytes where last byte has continuation bit (payload doesn't matter)
			{"overflow_mixed_payload", []byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A}, csproto.ErrValueOverflow},
			// 12 bytes all continuation — ensure we don't read past byte 10
			{"overflow_12byte", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, csproto.ErrValueOverflow},

			// Bug #1: 10th byte with payload bits above bit 0 should overflow.
			// Only values 0x00 and 0x01 are valid for the 10th byte since only
			// bit 0 (shifted to position 63) fits in a uint64. Values 0x02-0x7F
			// encode bits 64+ which silently overflow — these should be rejected.
			{"10th_byte_0x02_overwide", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}, csproto.ErrValueOverflow},
			{"10th_byte_0x03_overwide", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x03}, csproto.ErrValueOverflow},
			{"10th_byte_0x7f_overwide", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F}, csproto.ErrValueOverflow},
			{"10th_byte_0x40_overwide", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40}, csproto.ErrValueOverflow},
			// With real payload in earlier bytes — 10th byte still overwide
			{"10th_byte_overwide_with_payload", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02}, csproto.ErrValueOverflow},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				_, _, err := csproto.DecodeVarint(tc.input)
				assert.ErrorIs(t, err, tc.wantErr)
			})
		}
	})

	t.Run("truncated varints", func(t *testing.T) {
		t.Parallel()

		// For several multi-byte varints, truncate at each byte position and expect EOF
		truncCases := []struct {
			name string
			full []byte
		}{
			{"5byte_max_uint32", encode(math.MaxUint32)},
			{"10byte_max_uint64", encode(math.MaxUint64)},
			{"3byte_100000", encode(100000)},
			{"8byte_2^55", encode(1 << 55)},
		}
		for _, tc := range truncCases {
			for cutAt := 1; cutAt < len(tc.full); cutAt++ {
				name := fmt.Sprintf("%s_cut_at_%d_of_%d", tc.name, cutAt, len(tc.full))
				input := tc.full[:cutAt]
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					_, _, err := csproto.DecodeVarint(input)
					assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
				})
			}
		}
	})

	t.Run("powers of two", func(t *testing.T) {
		t.Parallel()
		for bit := 0; bit < 64; bit++ {
			val := uint64(1) << bit
			t.Run(fmt.Sprintf("2^%d", bit), func(t *testing.T) {
				t.Parallel()
				raw := encode(val)
				v, n, err := csproto.DecodeVarint(raw)
				require.NoError(t, err)
				assert.Equal(t, val, v)
				assert.Equal(t, len(raw), n)
			})
		}
	})

	t.Run("powers of two minus one", func(t *testing.T) {
		t.Parallel()
		for bit := 1; bit <= 63; bit++ {
			val := (uint64(1) << bit) - 1
			t.Run(fmt.Sprintf("2^%d-1", bit), func(t *testing.T) {
				t.Parallel()
				raw := encode(val)
				v, n, err := csproto.DecodeVarint(raw)
				require.NoError(t, err)
				assert.Equal(t, val, v)
				assert.Equal(t, len(raw), n)
			})
		}
	})

	t.Run("7-bit boundaries", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name  string
			val   uint64
			wantN int
		}{
			{"max_7bits", (1 << 7) - 1, 1},
			{"min_8bits", 1 << 7, 2},
			{"max_14bits", (1 << 14) - 1, 2},
			{"min_15bits", 1 << 14, 3},
			{"max_21bits", (1 << 21) - 1, 3},
			{"min_22bits", 1 << 21, 4},
			{"max_28bits", (1 << 28) - 1, 4},
			{"min_29bits", 1 << 28, 5},
			{"max_35bits", (1 << 35) - 1, 5},
			{"min_36bits", 1 << 35, 6},
			{"max_42bits", (1 << 42) - 1, 6},
			{"min_43bits", 1 << 42, 7},
			{"max_49bits", (1 << 49) - 1, 7},
			{"min_50bits", 1 << 49, 8},
			{"max_56bits", (1 << 56) - 1, 8},
			{"min_57bits", 1 << 56, 9},
			{"max_63bits", (1 << 63) - 1, 9},
			{"min_64bits", 1 << 63, 10},
			{"max_64bits", math.MaxUint64, 10},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				raw := encode(tc.val)
				require.Equal(t, tc.wantN, len(raw), "encoded length")
				v, n, err := csproto.DecodeVarint(raw)
				require.NoError(t, err)
				assert.Equal(t, tc.val, v)
				assert.Equal(t, tc.wantN, n)
			})
		}
	})

	t.Run("terminator at each position in sz9 buffer", func(t *testing.T) {
		t.Parallel()
		// Buffer of 9 bytes; place terminator (clear high bit) at each position 0-8
		for pos := 0; pos < 9; pos++ {
			buf := make([]byte, 9)
			for i := 0; i < pos; i++ {
				buf[i] = 0x80 | byte(i+1)
			}
			buf[pos] = byte(pos + 1) // terminal byte
			expectedN := pos + 1
			t.Run(fmt.Sprintf("term_at_%d", pos), func(t *testing.T) {
				t.Parallel()
				_, n, err := csproto.DecodeVarint(buf)
				require.NoError(t, err)
				assert.Equal(t, expectedN, n)
			})
		}
	})

	t.Run("early exit in each switch case", func(t *testing.T) {
		t.Parallel()
		// For each buffer size (sz) 2-9, test a varint that terminates at
		// every valid early byte position. This exercises all the early-return
		// branches within each switch case.
		for sz := 2; sz <= 9; sz++ {
			// Varint can terminate at positions 1 through sz-1 (early) or sz-1 (full use)
			for termAt := 1; termAt <= sz; termAt++ {
				buf := make([]byte, sz)
				// Bytes before terminator have continuation bit set
				for i := 0; i < termAt-1; i++ {
					buf[i] = 0x80 | byte(i+1)
				}
				// Terminator byte (high bit clear) — use position-based value
				buf[termAt-1] = byte(termAt)

				name := fmt.Sprintf("sz%d_term_at_byte%d", sz, termAt)
				expectedN := termAt
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					_, n, err := csproto.DecodeVarint(buf)
					require.NoError(t, err)
					assert.Equal(t, expectedN, n)
				})
			}

			// Also test the EOF case: all bytes have continuation bit, no terminator
			allCont := make([]byte, sz)
			for i := range allCont {
				allCont[i] = 0x80 | byte(i+1)
			}
			name := fmt.Sprintf("sz%d_all_continuation_eof", sz)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				_, _, err := csproto.DecodeVarint(allCont)
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
			})
		}
	})

	t.Run("early exit with real values in padded buffers", func(t *testing.T) {
		t.Parallel()
		// Encode short varints and place them in larger buffers so the sz
		// dispatches to a higher case but exits early at the real terminator.
		type testCase struct {
			name      string
			val       uint64
			varintLen int
		}
		vals := []testCase{
			{"2byte_val_300", 300, 2},
			{"3byte_val_100000", 100000, 3},
			{"4byte_val_40000000", 40000000, 4},
			{"5byte_val_5000000000", 5000000000, 5},
		}
		for _, tc := range vals {
			raw := encode(tc.val)
			require.Equal(t, tc.varintLen, len(raw))

			// Place in buffers of size varintLen+1 through 9
			for bufSz := tc.varintLen + 1; bufSz <= 9; bufSz++ {
				padded := make([]byte, bufSz)
				copy(padded, raw)
				// Remaining bytes are zero (which has high bit clear, but the varint
				// should terminate before reaching them)

				name := fmt.Sprintf("%s_in_buf%d", tc.name, bufSz)
				expectedVal := tc.val
				expectedN := tc.varintLen
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					v, n, err := csproto.DecodeVarint(padded)
					require.NoError(t, err)
					assert.Equal(t, expectedVal, v)
					assert.Equal(t, expectedN, n)
				})
			}
		}
	})

	t.Run("short path vs long path consistency", func(t *testing.T) {
		t.Parallel()
		// Same varint decoded from a tight buffer (short path, sz < 10)
		// and a padded buffer (long path, sz >= 10) must give identical results.
		tests := []uint64{
			128, 16384, 2097152, 268435456, 34359738368,
			4398046511104, 562949953421312, 72057594037927936,
		}
		for _, val := range tests {
			t.Run(fmt.Sprintf("val_%d", val), func(t *testing.T) {
				t.Parallel()
				raw := encode(val)
				require.Less(t, len(raw), 10)

				// Short path: exact-fit buffer
				v1, n1, err1 := csproto.DecodeVarint(raw)
				require.NoError(t, err1)

				// Long path: 10-byte buffer
				padded := make([]byte, 10)
				copy(padded, raw)
				v2, n2, err2 := csproto.DecodeVarint(padded)
				require.NoError(t, err2)

				assert.Equal(t, v1, v2, "values differ")
				assert.Equal(t, n1, n2, "byte counts differ")
			})
		}
	})

	t.Run("varint with trailing garbage", func(t *testing.T) {
		t.Parallel()
		// Decoder should consume only the varint bytes, not the garbage after
		tests := []struct {
			name  string
			val   uint64
			trail []byte
		}{
			{"1byte_trailing", 42, []byte{0xDE, 0xAD}},
			{"2byte_trailing", 300, []byte{0xBE, 0xEF, 0xCA}},
			{"5byte_trailing", math.MaxUint32, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				raw := encode(tc.val)
				input := append(raw, tc.trail...)
				v, n, err := csproto.DecodeVarint(input)
				require.NoError(t, err)
				assert.Equal(t, tc.val, v)
				assert.Equal(t, len(raw), n)
			})
		}
	})

	t.Run("negative int64 roundtrip", func(t *testing.T) {
		t.Parallel()
		// Protobuf encodes negative int64 as full 10-byte uint64
		negatives := []int64{-1, -128, -32768, math.MinInt64}
		for _, neg := range negatives {
			asUint := uint64(neg)
			t.Run(fmt.Sprintf("neg_%d", neg), func(t *testing.T) {
				t.Parallel()
				raw := encode(asUint)
				assert.Equal(t, 10, len(raw))
				v, n, err := csproto.DecodeVarint(raw)
				require.NoError(t, err)
				assert.Equal(t, asUint, v)
				assert.Equal(t, 10, n)
				assert.Equal(t, neg, int64(v))
			})
		}
	})
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
			case errors.Is(err, csproto.ErrInvalidFieldTag):
				// valid error
			default:
				t.Errorf("unexpected error from DecodeTag(): %v", err)
			}
		}
	})
}
