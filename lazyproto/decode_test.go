package lazyproto

import (
	"cmp"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/prototest"
)

func ExampleDecodeResult_FieldData() {
	// data contains the serialized bytes of an Example Protobuf message that is
	// defined as:
	//	message Example {
	//		int64  id     = 1;
	//		Nested nested = 2;
	//	}
	//	message Nested {
	//		string name        = 1;
	//		string description = 2;
	//	}
	data := []byte{
		// id: 1
		(1 << 3), 0x1,
		// nested: 10 bytes
		(2 << 3) | 2, 0x0A,
		// nested.name: foo
		(1 << 3) | 2, 0x03, 0x66, 0x6f, 0x6f,
		// nested.description: bar
		(2 << 3) | 2, 0x03, 0x62, 0x61, 0x72,
	}
	def := NewDef()
	// extract tags 1 and 2 from the nested message at tag 2 in the outer message
	_ = def.NestedTag(2, 1, 2)

	// create a new decoder for this definition
	dec, err := NewDecoder(def, WithMode(csproto.DecoderModeFast), WithMaxBufferSize(1024))
	if err != nil {
		fmt.Println("unable to create new decoder:", err)
		return
	}

	// decode arbitrary data
	res, err := dec.Decode(data)
	if err != nil {
		fmt.Println("error from decode:", err)
		return
	}
	defer func() {
		// Only close the result after we are completely done using it and any values we retrieved from it
		if err := res.Close(); err != nil {
			fmt.Println("error from DecodeResult.Close():", err)
		}
	}()
	// grab the field data
	nameData, err := res.FieldData(2, 1)
	if err != nil {
		fmt.Println("error accessing field data for 'name':", err)
		return
	}
	descriptionData, err := res.FieldData(2, 2)
	if err != nil {
		fmt.Println("error accessing field data for 'description':", err)
		return
	}
	// extract the values
	name, err := nameData.StringValue()
	if err != nil {
		fmt.Println("error retrieving string value for 'name':", err)
		return
	}
	description, err := descriptionData.StringValue()
	if err != nil {
		fmt.Println("error retrieving string value for 'description':", err)
		return
	}
	fmt.Printf("name: %s\ndescription: %s", name, description)
	// Output:
	// name: foo
	// description: bar
}

func FuzzStrings(f *testing.F) {
	for i, s := range []string{"hello", "world", "", " ", "123"} {
		f.Add(i, s)
	}
	const tagID = 123
	dec, err := NewDecoder(Def{tagID: nil})
	require.NoError(f, err)
	f.Fuzz(func(t *testing.T, n int, expected string) {
		var msg []byte
		for i := 0; i < n; i++ {
			sz := len(fmt.Sprintf("%s%d", expected, i))
			msg = append(msg, make([]byte, csproto.SizeOfTagKey(tagID)+csproto.SizeOfVarint(uint64(sz))+sz)...)
		}
		enc := csproto.NewEncoder(msg)
		for i := 0; i < n; i++ {
			enc.EncodeString(tagID, fmt.Sprintf("%s%d", expected, i))
		}
		result, err := dec.Decode(msg)
		require.NoError(t, err)
		v := checkErr(result.StringValue(tagID))(t, n)
		vs := checkErr(result.StringValues(tagID))(t, n)
		b := checkErr(result.BytesValue(tagID))(t, n)
		bs := checkErr(result.BytesValues(tagID))(t, n)
		if n <= 0 {
			return
		}

		exp := fmt.Sprintf("%s%d", expected, n-1)
		assert.EqualValues(t, exp, v)
		assert.EqualValues(t, exp, string(b))
		require.Len(t, vs, n)
		require.Len(t, bs, n)
		for i := 0; i < n; i++ {
			exp = fmt.Sprintf("%s%d", expected, i)
			assert.EqualValues(t, exp, vs[i])
			assert.EqualValues(t, exp, string(bs[i]))
		}
	})
}

func FuzzBools(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(2)
	f.Add(20)
	const tagID = 123
	dec, err := NewDecoder(Def{tagID: nil})
	require.NoError(f, err)
	f.Fuzz(func(t *testing.T, n int) {
		msg := make([]byte, max(n*(csproto.SizeOfTagKey(tagID)+1), 0))
		var expected []bool
		enc := csproto.NewEncoder(msg)
		for i := 0; i < n; i++ {
			expected = append(expected, n%3 == 0)
			enc.EncodeBool(tagID, n%3 == 0)
		}
		result, err := dec.Decode(msg)
		require.NoError(t, err)
		v := checkErr(result.BoolValue(tagID))(t, n)
		vs := checkErr(result.BoolValues(tagID))(t, n)
		if n <= 0 {
			return
		}
		assert.EqualValues(t, expected[len(expected)-1], v)
		assert.EqualValues(t, expected, vs)
	})
}

func FuzzNumbers(f *testing.F) {
	for i, v := range []float64{math.MinInt64, -100, -2, -1, 0, 1, 2, math.MaxUint64} {
		f.Add(i, v)
	}

	const (
		float32Tag = 1 + iota
		float64Tag
		int32Tag
		int64Tag
		fixed32Tag
		fixed64Tag
		sInt32Tag
		sInt64Tag
		uint32Tag
		uint64Tag
	)
	def := Def{}
	for i := float32Tag; i <= uint64Tag; i++ {
		def[i] = nil
	}
	dec, err := NewDecoder(def)
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, n int, expected float64) {
		var sz int
		for i := 0; i < n; i++ {
			exp := expected * float64(i)
			sz += csproto.SizeOfTagKey(float32Tag) + 4 +
				csproto.SizeOfTagKey(float64Tag) + 8 +
				csproto.SizeOfTagKey(int32Tag) + csproto.SizeOfVarint(uint64(int32(exp))) +
				csproto.SizeOfTagKey(int64Tag) + csproto.SizeOfVarint(uint64(int64(exp))) +
				csproto.SizeOfTagKey(fixed32Tag) + 4 +
				csproto.SizeOfTagKey(fixed64Tag) + 8 +
				csproto.SizeOfTagKey(sInt32Tag) + csproto.SizeOfZigZag(uint64(int32(exp))) +
				csproto.SizeOfTagKey(sInt64Tag) + csproto.SizeOfZigZag(uint64(int64(exp))) +
				csproto.SizeOfTagKey(uint32Tag) + csproto.SizeOfVarint(uint64(uint32(exp))) +
				csproto.SizeOfTagKey(uint64Tag) + csproto.SizeOfVarint(uint64(exp))
		}
		msg := make([]byte, sz)
		enc := csproto.NewEncoder(msg)
		for i := 0; i < n; i++ {
			exp := expected * float64(i)
			enc.EncodeFloat32(float32Tag, float32(exp))
			enc.EncodeFloat64(float64Tag, exp)
			t.Log("encoding", int32(exp))
			t.Log(msg)
			enc.EncodeInt32(int32Tag, int32(exp))
			t.Log(msg)
			enc.EncodeInt64(int64Tag, int64(exp))
			enc.EncodeFixed32(fixed32Tag, uint32(exp))
			enc.EncodeFixed64(fixed64Tag, uint64(exp))
			enc.EncodeSInt32(sInt32Tag, int32(exp))
			enc.EncodeSInt64(sInt64Tag, int64(exp))
			enc.EncodeUInt32(uint32Tag, uint32(exp))
			enc.EncodeUInt64(uint64Tag, uint64(exp))
		}
		result, err := dec.Decode(msg)
		require.NoError(t, err)
		exp := expected * float64(n-1)
		checkNum(result.Float32Value(float32Tag))(t, n, exp)
		checkNum(result.Float64Value(float64Tag))(t, n, exp)
		checkNum(result.Int32Value(int32Tag))(t, n, exp)
		checkNum(result.Int64Value(int64Tag))(t, n, exp)
		checkNum(result.Fixed32Value(fixed32Tag))(t, n, exp)
		checkNum(result.Fixed64Value(fixed64Tag))(t, n, exp)
		checkNum(result.SInt32Value(sInt32Tag))(t, n, exp)
		checkNum(result.SInt64Value(sInt64Tag))(t, n, exp)
		checkNum(result.UInt32Value(uint32Tag))(t, n, exp)
		checkNum(result.UInt64Value(uint64Tag))(t, n, exp)
		if t.Failed() {
			return
		}

		checkNums(result.Float32Values(float32Tag))(t, n, expected)
		checkNums(result.Float64Values(float64Tag))(t, n, expected)
		checkNums(result.Int32Values(int32Tag))(t, n, expected)
		checkNums(result.Int64Values(int64Tag))(t, n, expected)
		checkNums(result.Fixed32Values(fixed32Tag))(t, n, expected)
		checkNums(result.Fixed64Values(fixed64Tag))(t, n, expected)
		checkNums(result.SInt32Values(sInt32Tag))(t, n, expected)
		checkNums(result.SInt64Values(sInt64Tag))(t, n, expected)
		checkNums(result.UInt32Values(uint32Tag))(t, n, expected)
		checkNums(result.UInt64Values(uint64Tag))(t, n, expected)

	})
}

type number interface {
	~int32 | ~int64 | ~uint32 | ~uint64 | ~float32 | ~float64
}

func checkNum[T number](x T, err error) func(t testing.TB, n int, expected float64) {
	return func(t testing.TB, n int, expected float64) {
		if n <= 0 {
			assert.ErrorIs(t, err, ErrTagNotFound)
			assert.EqualValues(t, 0, cmp.Compare(x, T(0)))
			return
		}
		require.NoError(t, err)
		assert.EqualValues(t, 0, cmp.Compare(x, T(expected)))
	}
}

func checkNums[T number](x []T, err error) func(t testing.TB, n int, expected float64) {
	return func(t testing.TB, n int, expected float64) {
		t.Logf("N:%d, Expected:%f, ExpectedT:%+v, T:%T, actual:%+v", n, expected, T(expected), T(expected), x)
		if n <= 0 {
			assert.ErrorIs(t, err, ErrTagNotFound)
			return
		}
		require.NoError(t, err)
		require.Len(t, x, n)
		for i := 0; i < n; i++ {
			exp := expected * float64(i)
			assert.EqualValues(t, 0, cmp.Compare(x[i], T(exp)))
		}
	}
}

func checkErr[T any](x T, err error) func(t testing.TB, n int) T {
	return func(t testing.TB, n int) T {
		if n <= 0 {
			assert.ErrorIs(t, err, ErrTagNotFound)
			return x
		}
		require.NoError(t, err)
		return x
	}
}

func TestDecode(t *testing.T) {
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
		res, err := Decode([]byte{}, NewDef(1))
		defer func() { _ = res.Close() }()

		assert.NoError(t, err)
		assert.Empty(t, res.flatData)
	})
	t.Run("decode with nil def", func(t *testing.T) {
		t.Parallel()
		res, err := Decode([]byte{0x01}, nil)
		defer func() { _ = res.Close() }()

		assert.NoError(t, err)
		assert.Empty(t, res.flatData)
	})
	t.Run("decode with empty def", func(t *testing.T) {
		t.Parallel()
		res, err := Decode([]byte{0x01}, NewDef())
		defer func() { _ = res.Close() }()

		assert.NoError(t, err)
		assert.Empty(t, res.flatData)
	})
	t.Run("decode with missing def keys", func(t *testing.T) {
		t.Parallel()
		def := NewDef(42, 100)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()

		assert.NoError(t, err)
		assert.Empty(t, res.flatData[0].data)
	})
	t.Run("decode with matching def keys", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1, 2, 3, 4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()

		assert.NoError(t, err)
		assert.Len(t, res.flatData, 4, "should have 4 results")
	})
	t.Run("decode with nested def keys", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1, 2, 4)
		_ = def.NestedTag(3, 2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()

		assert.NoError(t, err)
		assert.Len(t, res.flatData, 4, "should have 4 results")
		fd, err := res.FieldData(3, 2)
		assert.NoError(t, err)
		assert.Len(t, fd.data, 1)
	})
	t.Run("get field data with nested def keys", func(t *testing.T) {
		t.Parallel()
		def := NewDef()
		_ = def.NestedTag(3, 2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3, 2)
		assert.NoError(t, err)
		assert.NotNil(t, fd)
		assert.Len(t, fd.data, 1)
	})
	t.Run("fails with invalid def", func(t *testing.T) {
		t.Parallel()
		def := NewDef(csproto.MaxTagValue + 1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.Empty(t, res.flatData)
		assert.Error(t, err)
	})
}

func TestDecodeResultFieldData(t *testing.T) {
	t.Parallel()
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
	t.Run("returns nil and not found error for nil result", func(t *testing.T) {
		t.Parallel()

		var res *DecodeResult
		fd, err := res.FieldData(1)
		assert.Nil(t, fd)
		assert.ErrorIs(t, err, ErrTagNotFound)
	})
	t.Run("returns nil and not found error for empty result", func(t *testing.T) {
		t.Parallel()

		var res DecodeResult
		fd, err := res.FieldData(1)
		assert.Nil(t, fd)
		assert.ErrorIs(t, err, ErrTagNotFound)
	})
	t.Run("returns nil and error when passed no tags", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1)
		res, _ := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		fd, err := res.FieldData()
		assert.Nil(t, fd)
		assert.Error(t, err)
		assert.Contains(t, fmt.Sprint(err), "at least one tag key must be specified")
	})
	t.Run("returns nil and error when passed incorrect negative tag", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1)
		res, _ := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		fd, err := res.FieldData(1, -1, 1)
		assert.Nil(t, fd)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTagNotFound)
		// negative tags no longer result in an error
		//assert.Contains(t, fmt.Sprint(err), "negative tags must be the last (or only) path item")
	})
	t.Run("returns nil and not found error for unmatched path", func(t *testing.T) {
		t.Parallel()

		def := NewDef()
		_ = def.NestedTag(3, 1)
		res, _ := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		fd, err := res.FieldData(3, 3)
		assert.Nil(t, fd)
		assert.ErrorIs(t, err, ErrTagNotFound)
	})
	t.Run("returns zero and not found error for nil field data", func(t *testing.T) {
		t.Parallel()
		var fd *FieldData

		// NOTE: dylan.bourque - 2023-01-11
		// . all the internal logic for all *Value() and *Values() methods is the same so we only need to test one
		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "scalar method should return 0")
		assert.ErrorIs(t, err, ErrTagNotFound)

		vs, err := fd.UInt32Values()
		assert.Nil(t, vs, "slice method should return nil")
		assert.ErrorIs(t, err, ErrTagNotFound)
	})
	t.Run("returns zero and not found error for empty field data", func(t *testing.T) {
		t.Parallel()
		var fd FieldData

		// NOTE: dylan.bourque - 2023-01-11
		// . all the internal logic for all *Value() and *Values() methods is the same so we only need to test one
		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "scalar method should return 0")
		assert.ErrorIs(t, err, ErrTagNotFound)

		vs, err := fd.UInt32Values()
		assert.Nil(t, vs, "slice method should return nil")
		assert.ErrorIs(t, err, ErrTagNotFound)
	})
}

func TestRawFieldData(t *testing.T) {
	t.Parallel()
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
	t.Run("with valid tag path", func(t *testing.T) {
		t.Parallel()
		def := NewDef()
		// negative tag for raw data
		def = def.Tags(-3)
		// positive tag for individual field(s)
		_ = def.NestedTag(3, 2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)
		defer res.Close()

		fd, err := res.FieldData(-3)
		assert.NoError(t, err)
		assert.NotNil(t, fd)

		d, err := fd.BytesValue()
		assert.NoError(t, err)
		assert.Equal(t, sampleMessage[13:23], d)
	})
	t.Run("with invalid tag path", func(t *testing.T) {
		t.Parallel()
		def := NewDef()
		// negative tag for raw data
		def = def.Tags(-3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)
		defer res.Close()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		b, err := fd.BoolValue()
		assert.NoError(t, err)
		assert.True(t, b)
	})
	t.Run("repeated boolean", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		s, err := fd.StringValue()
		assert.NoError(t, err)
		assert.Equal(t, "test", s)
	})
	t.Run("repeated string", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		b, err := fd.BytesValue()
		assert.NoError(t, err)
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, b)
	})
	t.Run("repeated bytes", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(0), v)
	})
	t.Run("regular uint32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(42), v)
	})
	t.Run("max uint32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(math.MaxUint32), v)
	})
	t.Run("repeated uint32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
	t.Run("uint32 overflow", func(t *testing.T) {
		t.Parallel()
		def := NewDef(7)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(7)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "should return 0")
		assert.ErrorIs(t, err, csproto.ErrValueOverflow, "should return ErrValueOverflow error")
	})
}

func TestInt32FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: int32 (0)
		(1 << 3), 0x00,
		// field 2: regular int32 (42)
		(2 << 3), 0x2a,
		// field 3: negative int32 (-42)
		(3 << 3), 0xD6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		// field 4: max int32 (2,147,483,647)
		(4 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0x07,
		// field 5: min int32 (-2,147,483,647)
		(5 << 3), 0x80, 0x80, 0x80, 0x80, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		// field 6: regular repeated int32 - 1, 2, 3
		(6 << 3), 0x01,
		(6 << 3), 0x02,
		(6 << 3), 0x03,
		// field 7: packed repeated int32 - 4, 5, 6
		(7 << 3) | 2, 0x03, 0x04, 0x05, 0x06,
		// field 8: fixed32 (invalid for int32 value)
		(8 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
		// field 9: varint int32 overflow (max int32 + 1)
		(9 << 3), 0x80, 0x80, 0x80, 0x80, 0x08,
	}
	t.Parallel()
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(0), v)
	})
	t.Run("regular int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(42), v)
	})
	t.Run("negative int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(-42), v)
	})
	t.Run("max int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(math.MaxInt32), v)
	})
	t.Run("min int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(math.MinInt32), v)
	})
	t.Run("repeated int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		vs, err := fd.Int32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int32{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(7)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(7)
		assert.NoError(t, err)

		vs, err := fd.Int32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int32{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(8)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(8)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.Equal(t, int32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
	t.Run("int32 overflow", func(t *testing.T) {
		t.Parallel()
		def := NewDef(9)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(9)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.Equal(t, int32(0), v, "should return 0")
		assert.ErrorIs(t, err, csproto.ErrValueOverflow, "should return ErrValueOverflow error")
	})
}

func TestSInt32FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: int32 (0)
		(1 << 3), 0x00,
		// field 2: regular int32 (42)
		(2 << 3), 0x54,
		// field 3: negative int32 (-42)
		(3 << 3), 0x53,
		// field 4: max int32 (2,147,483,647)
		(4 << 3), 0xFE, 0xFF, 0xFF, 0xFF, 0x0F,
		// field 5: min int32 (-2,147,483,647)
		(5 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0x0F,
		// field 6: regular repeated int32 - 1, 2, 3
		(6 << 3), 0x02,
		(6 << 3), 0x04,
		(6 << 3), 0x06,
		// field 7: packed repeated int32 - 4, 5, 6
		(7 << 3) | 2, 0x03, 0x08, 0x0A, 0x0C,
		// field 8: fixed32 (invalid for int32 value)
		(8 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
		// field 9: varint int32 overflow (max int32 + 1)
		(9 << 3), 0x80, 0x80, 0x80, 0x80, 0x08,
	}
	t.Parallel()
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.SInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(0), v)
	})
	t.Run("regular int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.SInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(42), v)
	})
	t.Run("negative int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.SInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(-42), v)
	})
	t.Run("max int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		v, err := fd.SInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(math.MaxInt32), v)
	})
	t.Run("min int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		v, err := fd.SInt32Value()
		assert.NoError(t, err)
		assert.Equal(t, int32(math.MinInt32), v)
	})
	t.Run("repeated int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		vs, err := fd.SInt32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int32{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated int32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(7)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(7)
		assert.NoError(t, err)

		vs, err := fd.SInt32Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int32{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(8)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(8)
		assert.NoError(t, err)

		v, err := fd.SInt32Value()
		assert.Equal(t, int32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
	t.Run("int32 overflow", func(t *testing.T) {
		t.Parallel()
		def := NewDef(9)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(9)
		assert.NoError(t, err)

		v, err := fd.Int32Value()
		assert.Equal(t, int32(0), v, "should return 0")
		assert.ErrorIs(t, err, csproto.ErrValueOverflow, "should return ErrValueOverflow error")
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.UInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), v)
	})
	t.Run("regular uint64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.UInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(42), v)
	})
	t.Run("max uint64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.UInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(math.MaxUint64), v)
	})
	t.Run("repeated uint64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.UInt32Value()
		assert.Equal(t, uint32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func TestInt64FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: int64 (0)
		(1 << 3), 0x00,
		// field 2: regular int64 (42)
		(2 << 3), 0x2a,
		// field 3: negative int64 (-42)
		(3 << 3), 0xD6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		// field 4: max int64 (9,223,372,036,854,775,808)
		(4 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
		// field 5: min int64 (-9,223,372,036,854,775,808)
		(5 << 3), 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
		// field 6: regular repeated int64 - 1, 2, 3
		(6 << 3), 0x01,
		(6 << 3), 0x02,
		(6 << 3), 0x03,
		// field 7: packed repeated int64 - 4, 5, 6
		(7 << 3) | 2, 0x03, 0x04, 0x05, 0x06,
		// field 8: fixed32 (invalid for int64 value)
		(8 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
		// field 9: varint int32 overflow (max int32 + 1)
		(9 << 3), 0x80, 0x80, 0x80, 0x80, 0x08,
		// field 10: varint int32 underflow (min int32 - 1)
		(10 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0xF7, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
	}
	t.Parallel()
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(0), v)
	})
	t.Run("regular int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(42), v)
	})
	t.Run("negative int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(-42), v)
	})
	t.Run("max int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MaxInt64), v)
	})
	t.Run("min int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MinInt64), v)
	})
	t.Run("repeated int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		vs, err := fd.Int64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int64{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(7)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(7)
		assert.NoError(t, err)

		vs, err := fd.Int64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int64{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(8)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(8)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.Equal(t, int64(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
	t.Run("max int32 + 1", func(t *testing.T) {
		t.Parallel()
		def := NewDef(9)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(9)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MaxInt32+1), v)
	})
	t.Run("min int32 - 1", func(t *testing.T) {
		t.Parallel()
		def := NewDef(10)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(10)
		assert.NoError(t, err)

		v, err := fd.Int64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MinInt32-1), v)
	})
}

func TestSInt64FieldData(t *testing.T) {
	var sampleMessage = []byte{
		// field 1: int64 (0)
		(1 << 3), 0x00,
		// field 2: regular int64 (42)
		(2 << 3), 0x54,
		// field 3: negative int64 (-42)
		(3 << 3), 0x53,
		// field 4: max int64 (9,223,372,036,854,775,808)
		(4 << 3), 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		// field 5: min int64 (-9,223,372,036,854,775,808)
		(5 << 3), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		// field 6: regular repeated int64 - 1, 2, 3
		(6 << 3), 0x02,
		(6 << 3), 0x04,
		(6 << 3), 0x06,
		// field 7: packed repeated int64 - 4, 5, 6
		(7 << 3) | 2, 0x03, 0x08, 0x0a, 0x0c,
		// field 8: fixed32 (invalid for int64 value)
		(8 << 3) | 5, 0x00, 0x01, 0x02, 0x03,
		// field 9: varint int32 overflow (max int32 + 1)
		(9 << 3), 0x80, 0x80, 0x80, 0x80, 0x10,
		// field 10: varint int32 underflow (min int32 - 1)
		(10 << 3), 0x81, 0x80, 0x80, 0x80, 0x10,
	}
	t.Parallel()
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(0), v)
	})
	t.Run("regular int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(42), v)
	})
	t.Run("negative int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(-42), v)
	})
	t.Run("max int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(4)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MaxInt64), v)
	})
	t.Run("min int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(5)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MinInt64), v)
	})
	t.Run("repeated int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		vs, err := fd.SInt64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int64{1, 2, 3} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("packed repeated int64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(7)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(7)
		assert.NoError(t, err)

		vs, err := fd.SInt64Values()
		assert.NoError(t, err)
		assert.Len(t, vs, 3)
		for i, expected := range []int64{4, 5, 6} {
			assert.Equal(t, expected, vs[i], "mismatched values at index %d", i)
		}
	})
	t.Run("tag not present", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(8)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(8)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.Equal(t, int64(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
	t.Run("max int32 + 1", func(t *testing.T) {
		t.Parallel()
		def := NewDef(9)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(9)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MaxInt32+1), v)
	})
	t.Run("min int32 - 1", func(t *testing.T) {
		t.Parallel()
		def := NewDef(10)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(10)
		assert.NoError(t, err)

		v, err := fd.SInt64Value()
		assert.NoError(t, err)
		assert.Equal(t, int64(math.MinInt32-1), v)
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Fixed32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(0), v)
	})
	t.Run("regular fixed32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Fixed32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(1138), v)
	})
	t.Run("max fixed32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Fixed32Value()
		assert.NoError(t, err)
		assert.Equal(t, uint32(math.MaxUint32), v)
	})
	t.Run("repeated fixed32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Fixed64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), v)
	})
	t.Run("regular fixed64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Fixed64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(1138), v)
	})
	t.Run("max fixed64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Fixed64Value()
		assert.NoError(t, err)
		assert.Equal(t, uint64(math.MaxUint64), v)
	})
	t.Run("repeated fixed64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.NoError(t, err)
		assert.Equal(t, float32(0), v)
	})
	t.Run("regular float32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.NoError(t, err)
		assert.Equal(t, float32(42.1138), v)
	})
	t.Run("max float32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.NoError(t, err)
		assert.Equal(t, float32(math.MaxFloat32), v)
	})
	t.Run("repeated float32", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.Float32Value()
		assert.Equal(t, float32(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(1)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.NoError(t, err)
		assert.Equal(t, float64(0), v)
	})
	t.Run("regular float64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(2)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.NoError(t, err)
		assert.Equal(t, float64(42.1138), v)
	})
	t.Run("max float64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(3)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(3)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.NoError(t, err)
		assert.Equal(t, float64(math.MaxFloat64), v)
	})
	t.Run("repeated float64", func(t *testing.T) {
		t.Parallel()
		def := NewDef(4)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(5)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
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
		def := NewDef(1)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(2)
		assert.ErrorIs(t, err, ErrTagNotFound)
		assert.Nil(t, fd)
	})
	t.Run("incorrect wire type", func(t *testing.T) {
		t.Parallel()
		var expectedErr *WireTypeMismatchError
		def := NewDef(6)
		res, err := Decode(sampleMessage, def)
		defer func() { _ = res.Close() }()
		assert.NoError(t, err)

		fd, err := res.FieldData(6)
		assert.NoError(t, err)

		v, err := fd.Float64Value()
		assert.Equal(t, float64(0), v, "should return 0")
		assert.ErrorAs(t, err, &expectedErr, "should return a WireTypeMismatchError error")
	})
}

func Test_Issue158(t *testing.T) {
	// this test verified the bug, and subsequent fix, for Issue #159 (https://github.com/CrowdStrike/csproto/issues/158)

	// This is the encoded content of a representative message that led to the panic noted in the
	// linked issue. Roughly, there is an outer "envelope" message with a type discriminant where
	// the "payload" data is defined by a proto2 extension field.  In this case, the payload contains
	// a bytes field that is itself an encoded proto message.
	//
	// In broad terms, the messages look like this:
	//	enum MessageType {
	//		...
	//	}
	//	message Envelope {
	//		extensions 100 to max;
	//		required MessageType messageType = 1;
	//		...
	//	}
	//	message WrappedMessagePayload {
	//		extend Envelope {
	//			optional WrappedMessagePayload payload = 100;
	//		}
	//		required uint32 eventTypeID = 1;
	//		required bytes dataBytes = 2;
	//		...
	//	}
	//
	// And the wrapped message looks like:
	//	message InnerMessage {
	//		...
	//		optional uint64 processID = 6;
	//		...
	//		optional uint32 patternID = 74;
	//		...
	//		optional string metadata = 503;
	//		...
	//		optional uint32 templateID = 744;
	//		...
	//	}
	//
	// Specifically for this bug, the upstream system generated a corrupted message where the length of
	// the InnerMessage.metadata field was very large, which resulted in a negative value when converted
	// from uint64 to int.  That negative value was then used inside of Skip() to update the decoder's
	// read offset and, subseqeuently, to extract the sub-slice containing the skipped field.
	const data = `; envelope
08 ; tag=1 (messageType), varint
  64 ; value=100 (payload type = WrappedMessagePayload)
A2 06 ; tag=100 (WrappedMessagePayload extension), length-delimited
  1B ; len=27
  08 ; tag=1 (eventTypeId), varint
    01 ; value=1
  12 ; tag=2 (dataBytes), length-delimited
  	17 ; len=23
  	; InnerMessage
    30 ; tag=6 (processID), varint
      01 ; value=1
    D0 04 ; tag=74 (patternID), varint
      01 ; value=1
    BA 1F ; tag=503 (metadata), length-delimited
      ; * CORRUPT VALUE *
      ; 11,686,238,624,781,661,536 is a valid varint value but overflows the range of int and
      ; becomes negative when converted from uint64
      E0 EA BD B4 CE 83 F7 96 A2 01 ; len=11x10^18
      66 6F 6F ; "foo"
    C0 2E ; tag=744 (templateID), varint
      01 ; value=1`

	bb, _ := prototest.ParseAnnotatedHex(data)
	def := NewDef()
	def.NestedTag(100, 2)
	res, err := Decode(bb, def)
	require.NoError(t, err, "error from first Decode()")

	fd, err := res.FieldData(100, 2)
	require.NoError(t, err, "error extracting field data from extension")

	evt, err := fd.BytesValue()
	require.NoError(t, err, "error extracting bytes from field data")

	// these Decode() calls should fail due to the corrupt field length
	_, err = Decode(evt, NewDef(74))
	assert.Error(t, err, "expected error from Decode() when data is corrupted")
	_, err = Decode(evt, NewDef(744))
	assert.Error(t, err, "expected error from Decode() when data is corrupted")
}
