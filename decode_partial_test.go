package csproto

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodePartial(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: varint boolean true
		(1 << 3), 0x01,
		// field 2: string "testing"
		(2 << 3) | 2, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67,
		// field 3: nested message (10 bytes)
		// . field 1: integer 5
		// . field 2: string "nested"
		(3 << 3) | 2, 0x0a, (1 << 3), 0x05, (2<<3 | 2), 0x06, 0x6e, 0x65, 0x73, 0x74, 0x65, 0x64,
		// field 4: fixed32 1138
		(4 << 3) | 5, 0x72, 0x04, 0x00, 0x00,
		// field 5: float64 42.1138
		(5 << 3) | 1, 0x74, 0x24, 0x97, 0xFF, 0x90, 0x0E, 0x45, 0x40,
	}
	t.Parallel()
	t.Run("decode empty buffer", func(t *testing.T) {
		t.Parallel()
		res, err := DecodePartial([]byte{}, map[int]any{1: nil})

		assert.NoError(t, err)
		assert.Empty(t, res.m)
	})
	t.Run("decode with nil def", func(t *testing.T) {
		t.Parallel()
		res, err := DecodePartial([]byte{0x01}, nil)

		assert.NoError(t, err)
		assert.Empty(t, res.m)
	})
	t.Run("decode with empty def", func(t *testing.T) {
		t.Parallel()
		res, err := DecodePartial([]byte{0x01}, map[int]any{})

		assert.NoError(t, err)
		assert.Empty(t, res.m)
	})
	t.Run("decode with missing def keys", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			42:  nil,
			100: nil,
		}
		res, err := DecodePartial(sampleMessage, def)

		assert.NoError(t, err)
		assert.Empty(t, res.m)
	})
	t.Run("decode with matching def keys", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
			2: nil,
			3: nil,
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)

		assert.NoError(t, err)
		assert.Len(t, res.m, 4, "should have 4 results")
	})
	t.Run("decode with nested def keys", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
			2: nil,
			3: map[int]any{
				2: nil,
			},
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)

		assert.NoError(t, err)
		assert.Len(t, res.m, 4, "should have 4 results")
		fd := res.m[3]
		assert.Len(t, fd.data, 1)
	})
	t.Run("get field data with nested def keys", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			3: map[int]any{
				2: nil,
			},
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3, 2)
		assert.NoError(t, err)
		assert.NotNil(t, fd)
		assert.Len(t, fd.data, 1)
	})
}

func TestBooleanFieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: varint boolean true
		(1 << 3), 0x01,
		// field 2: regular repeated boolean - true, true, false
		(2 << 3), 0x01,
		(2 << 3), 0x01,
		(2 << 3), 0x00,
		// field 3: packed repeated boolean - true, false, true
		(3 << 3) | 2, 0x03, 0x01, 0x00, 0x01,
		// field 4: fixed32 (invalid for bool value)
		(4 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
	}
	t.Parallel()
	t.Run("single boolean", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		b, err := fd.BoolValue()
		assert.NoError(t, err)
		assert.True(t, b)
	})
	t.Run("repeated boolean", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		bs, err := fd.BoolValues()
		assert.NoError(t, err)
		assert.Len(t, bs, 3)
		for i, expected := range []bool{true, true, false} {
			assert.Equal(t, expected, bs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		v, err := fd.BoolValue()
		assert.False(t, v, "should return false")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestStringFieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: single string - "test"
		(1 << 3) | 2, 0x04, 0x74, 0x65, 0x73, 0x74,
		// field 2: repeated string - "one", "two"
		(2 << 3) | 2, 0x03, 0x6f, 0x6e, 0x65,
		(2 << 3) | 2, 0x03, 0x74, 0x77, 0x6f,
		// field 3: fixed32 (invalid for string value)
		(3 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
	}
	t.Parallel()
	t.Run("single string", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		s, err := fd.StringValue()
		assert.NoError(t, err)
		assert.Equal(t, "test", s)
	})
	t.Run("repeated string", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		ss, err := fd.StringValues()
		assert.NoError(t, err)
		assert.Len(t, ss, 2)
		for i, expected := range []string{"one", "two"} {
			assert.Equal(t, expected, ss[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.StringValue()
		assert.Equal(t, "", v, "should return false")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestBytesFieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: single bytes - [1,2,3,4]
		(1 << 3) | 2, 0x04, 0x01, 0x02, 0x03, 0x04,
		// field 2: repeated bytes - [1,2], [3,4]
		(2 << 3) | 2, 0x02, 0x01, 0x02,
		(2 << 3) | 2, 0x02, 0x03, 0x04,
		// field 3: fixed32 (invalid for bytes value)
		(3 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
	}
	t.Parallel()
	t.Run("single bytes", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		b, err := fd.BytesValue()
		assert.NoError(t, err)
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, b)
	})
	t.Run("repeated bytes", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		bs, err := fd.BytesValues()
		assert.NoError(t, err)
		assert.Len(t, bs, 2)
		for i, expected := range [][]byte{{0x01, 0x02}, {0x03, 0x04}} {
			assert.Equal(t, expected, bs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.StringValue()
		assert.Equal(t, "", v, "should return false")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestUInt32FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: min uint32 (0)
		(1 << 3), 0x00,
		// field 2: regular uint32 (42)
		(2 << 3), 0x2a,
		// field 3: max uint32 (4,294,967,295)
		(3 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0x0F,
		// field 4: regular repeated uint32 - 1, 2, 3
		(4 << 3), 0x01,
		(4 << 3), 0x02,
		(4 << 3), 0x03,
		// field 5: packed repeated uint32 - 4, 5, 6
		(5 << 3) | 2, 0x03, 0x04, 0x05, 0x06,
		// field 6: fixed32 (invalid for uint32 value)
		(6 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
		// field 7: varint uint32 overflow (max uint32 + 1)
		(7 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0x10,
	}
	t.Parallel()
	t.Run("min uint32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(0), v)
	})
	t.Run("regular uint32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(42), v)
	})
	t.Run("max uint32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(math.MaxUint32), v)
	})
	t.Run("repeated uint32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		vs, err := fd.UInt32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint32{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated uint32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			5: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		vs, err := fd.UInt32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint32{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			6: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
	t.Run("uint32 overflow", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			7: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(7)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "should return 0")
		assert.ErrorIs(t, err, ErrValueOverflow, "should return ErrValueOverflow error")
	})
}

func TestUInt64FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: min uint64 (0)
		(1 << 3), 0x00,
		// field 2: regular uint64 (42)
		(2 << 3), 0x2a,
		// field 3: max uint64 (18,446,744,073,709,551,615)
		(3 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		// field 4: regular repeated uint64 - 1, 2, 3
		(4 << 3), 0x01,
		(4 << 3), 0x02,
		(4 << 3), 0x03,
		// field 5: packed repeated uint64 - 4, 5, 6
		(5 << 3) | 2, 0x03, 0x04, 0x05, 0x06,
		// field 6: fixed32 (invalid for uint32 value)
		(6 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
	}
	t.Parallel()
	t.Run("min uint64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.UInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), v)
	})
	t.Run("regular uint64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.UInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(42), v)
	})
	t.Run("max uint64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.UInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(math.MaxUint64), v)
	})
	t.Run("repeated uint64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		vs, err := fd.UInt64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint64{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated uint64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			5: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		vs, err := fd.UInt64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint64{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			6: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestFixed32FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: min fixed32 (0)
		(1 << 3) | 5, 0x00, 0x00, 0x00, 0x00,
		// field 2: regular fixed32 (1138)
		(2 << 3) | 5, 0x72, 0x04, 0x00, 0x00,
		// field 3: max fixed32 (4,294,967,295)
		(3 << 3) | 5, 0xFF, 0xFF, 0xFF, 0xFF,
		// field 4: regular repeated fixed32 - 1, 2, 3
		(4 << 3) | 5, 0x01, 0x00, 0x00, 0x00,
		(4 << 3) | 5, 0x02, 0x00, 0x00, 0x00,
		(4 << 3) | 5, 0x03, 0x00, 0x00, 0x00,
		// field 5: packed repeated fixed32 - 4, 5, 6
		(5 << 3) | 2, 0x0C, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
		// field 6: varint (invalid for fixed32 value)
		(6 << 3), 0x00,
	}
	t.Parallel()
	t.Run("min fixed32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Fixed32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(0), v)
	})
	t.Run("regular fixed32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Fixed32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(1138), v)
	})
	t.Run("max fixed32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Fixed32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(math.MaxUint32), v)
	})
	t.Run("repeated fixed32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		vs, err := fd.Fixed32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint32{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated fixed32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			5: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		vs, err := fd.Fixed32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint32{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			6: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.Fixed32Value()
		assert.Equal(t, uint32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestFixed64FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: min fixed64 (0)
		(1 << 3) | 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// field 2: regular fixed64 (1138)
		(2 << 3) | 1, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// field 3: max fixed64 (18,446,744,073,709,551,615)
		(3 << 3) | 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		// field 4: regular repeated fixed64 - 1, 2, 3
		(4 << 3) | 1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		(4 << 3) | 1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		(4 << 3) | 1, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// field 5: packed repeated fixed64 - 4, 5, 6
		(5 << 3) | 2, 0x18,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// field 6: varint (invalid for fixed64 value)
		(6 << 3), 0x00,
	}
	t.Parallel()
	t.Run("min fixed64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Fixed64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), v)
	})
	t.Run("regular fixed64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Fixed64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(1138), v)
	})
	t.Run("max fixed64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Fixed64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(math.MaxUint64), v)
	})
	t.Run("repeated fixed64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		vs, err := fd.Fixed64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint64{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated fixed64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			5: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		vs, err := fd.Fixed64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []uint64{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			6: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.Fixed64Value()
		assert.Equal(t, uint64(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestFloat32FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: zero float32 (0)
		(1 << 3) | 5, 0x00, 0x00, 0x00, 0x00,
		// field 2: regular float32 (42.1138)
		(2 << 3) | 5, 0x88, 0x74, 0x28, 0x42,
		// field 3: max float32 (math.MaxFloat32, ~3.4028235 x 10^38)
		(3 << 3) | 5, 0xFF, 0xFF, 0x7F, 0x7F,
		// field 4: regular repeated float32 - 1.2, 3.4, 5.6
		(4 << 3) | 5, 0x9A, 0x99, 0x99, 0x3F,
		(4 << 3) | 5, 0x9A, 0x99, 0x59, 0x40,
		(4 << 3) | 5, 0x33, 0x33, 0xB3, 0x40,
		// field 5: packed repeated float32 - 1.2, 3.4, 5.6
		(5 << 3) | 2, 0x0C, 0x9A, 0x99, 0x99, 0x3F, 0x9A, 0x99, 0x59, 0x40, 0x33, 0x33, 0xB3, 0x40,
		// field 6: varint (invalid for float32 value)
		(6 << 3), 0x00,
	}
	t.Parallel()
	t.Run("min float32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.NoError(t, err)
		assert.Equal(t, float32(0), v)
	})
	t.Run("regular float32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.NoError(t, err)
		assert.Equal(t, float32(42.1138), v)
	})
	t.Run("max float32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.NoError(t, err)
		assert.Equal(t, float32(math.MaxFloat32), v)
	})
	t.Run("repeated float32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		vs, err := fd.Float32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []float32{1.2, 3.4, 5.6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated float32", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			5: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		vs, err := fd.Float32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []float32{1.2, 3.4, 5.6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			6: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.Equal(t, float32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestXxx(t *testing.T) {
	vs := []float64{
		0.0,
		1.2,
		3.4,
		5.6,
		42.1138,
		math.MaxFloat64,
	}
	for _, v := range vs {
		var b [9]byte
		NewEncoder(b[:]).EncodeFloat64(1, v)
		var sb strings.Builder
		for _, bb := range b {
			sb.WriteString(fmt.Sprintf("0x%02X, ", bb))
		}
		t.Log(v, "->", sb.String())
	}
}

func TestFloat64FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: float64 (0)
		(1 << 3) | 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// field 2: regular float64 (42.1138)
		(2 << 3) | 1, 0x74, 0x24, 0x97, 0xFF, 0x90, 0x0E, 0x45, 0x40,
		// field 3: max float64 (math.MaxFloat64, ~1.7976931348623157 x 10^308)
		(3 << 3) | 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F,
		// field 4: regular repeated float64 - 1.2, 3.4, 5.6
		(4 << 3) | 1, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0xF3, 0x3F,
		(4 << 3) | 1, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x0B, 0x40,
		(4 << 3) | 1, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x16, 0x40,
		// field 5: packed repeated float64 - 1.2, 3.4, 5.6
		(5 << 3) | 2, 0x18,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0xF3, 0x3F,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x0B, 0x40,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x16, 0x40,
		// field 6: varint (invalid for float64 value)
		(6 << 3), 0x00,
	}
	t.Parallel()
	t.Run("min float64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.NoError(t, err)
		assert.Equal(t, float64(0), v)
	})
	t.Run("regular float64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			2: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.NoError(t, err)
		assert.Equal(t, float64(42.1138), v)
	})
	t.Run("max float64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			3: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.NoError(t, err)
		assert.Equal(t, float64(math.MaxFloat64), v)
	})
	t.Run("repeated float64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			4: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		vs, err := fd.Float64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []float64{1.2, 3.4, 5.6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated float64", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			5: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		vs, err := fd.Float64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []float64{1.2, 3.4, 5.6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := map[int]any{
			1: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := map[int]any{
			6: nil,
		}
		res, err := DecodePartial(sampleMessage, def)
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.Equal(t, float64(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}
