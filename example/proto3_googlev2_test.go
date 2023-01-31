package example_test

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto3/googlev2"
)

func TestProto3GoogleV2Message(t *testing.T) {
	msg := createTestProto3GoogleV2Message()

	t.Run("google_marshal/csproto_unmarshal", func(t *testing.T) {
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using golang/protobuf: %v", err)
			t.FailNow()
		}

		var msg2 googlev2.TestEvent
		if err = csproto.Unmarshal(data, &msg2); err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}
	})
	t.Run("csproto_marshal/google_unmarshal", func(t *testing.T) {
		data, err := csproto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using csproto: %v", err)
			t.FailNow()
		}

		var msg2 googlev2.TestEvent
		if err = proto.Unmarshal(data, &msg2); err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}

	})
}

func TestProto3GoogleV2MarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := timestamppb.Now()
		msg := googlev2.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: googlev2.EventType_EVENT_TYPE_ONE,
		}
		expected := fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGoogleTimestampString(ts))

		res, err := csproto.JSONMarshaler(&msg).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		ts := timestamppb.Now()
		msg := googlev2.EventUsingWKTs{
			Name:      "with-indent",
			Ts:        ts,
			EventType: googlev2.EventType_EVENT_TYPE_ONE,
		}
		expected := fmt.Sprintf("{\n\t\"name\": \"with-indent\",\n\t\"ts\": \"%s\",\n\t\"eventType\": \"EVENT_TYPE_ONE\"\n}", genGoogleTimestampString(ts))

		opts := []csproto.JSONOption{
			csproto.JSONIndent("\t"),
		}
		res, err := csproto.JSONMarshaler(&msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
		// compare the actual string
		// - validate the formatted JSON text output, including line breaks and indentation
		// - replace ":  " with ": " to undo the Google library's intentional randomization of the output :(
		//   see: https://github.com/protocolbuffers/protobuf-go/blob/v1.28.1/internal/encoding/json/encode.go#L268-L274
		s := strings.ReplaceAll(string(res), ":  ", ": ")
		assert.Equal(t, expected, s)
	})
	t.Run("exclude-zero-values", func(t *testing.T) {
		msg := googlev2.EventUsingWKTs{
			Name: "exclude-zero-values",
		}
		expected := `{"name":"exclude-zero-values"}`

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(false),
		}
		res, err := csproto.JSONMarshaler(&msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("include-zero-values", func(t *testing.T) {
		msg := googlev2.EventUsingWKTs{
			Name: "include-zero-values",
		}
		expected := `{"name":"include-zero-values","ts":null,"eventType":"EVENT_TYPE_UNDEFINED"}`

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(true),
		}
		res, err := csproto.JSONMarshaler(&msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("enable-all", func(t *testing.T) {
		etype := googlev2.EventType_EVENT_TYPE_UNDEFINED
		msg := googlev2.EventUsingWKTs{
			Name:      "enable-all",
			EventType: etype,
		}
		expected := fmt.Sprintf("{\n  \"name\": \"enable-all\",\n  \"ts\": null,\n  \"eventType\": 0\n}")

		opts := []csproto.JSONOption{
			csproto.JSONIndent("  "),
			csproto.JSONIncludeZeroValues(true),
			csproto.JSONUseEnumNumbers(true),
		}
		res, err := csproto.JSONMarshaler(&msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
}

func TestProto3GoogleV2UnmarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGoogleTimestampString(ts)))
		var msg googlev2.EventUsingWKTs
		expected := googlev2.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: googlev2.EventType_EVENT_TYPE_ONE,
		}

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.NoError(t, err)
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("with-unknown-fields", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGoogleTimestampString(ts)))
		var msg googlev2.EventUsingWKTs

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.Error(t, err, "JSON unmarshaling should fail if there are unknown fields")
	})
	t.Run("allow-unknown-fields", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGoogleTimestampString(ts)))
		var msg googlev2.EventUsingWKTs
		expected := googlev2.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: googlev2.EventType_EVENT_TYPE_ONE,
		}

		opts := []csproto.JSONOption{
			csproto.JSONAllowUnknownFields(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.NoError(t, err)
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("with-missing-required-fields", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGoogleTimestampString(ts)))
		var msg googlev2.EventUsingWKTs
		expected := googlev2.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: googlev2.EventType_EVENT_TYPE_ONE,
		}

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.NoError(t, err, "JSON unmarshaling should not fail since proto3 does not have required fields")
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("allow-partial", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGoogleTimestampString(ts)))
		var msg googlev2.EventUsingWKTs
		expected := googlev2.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: googlev2.EventType_EVENT_TYPE_ONE,
		}

		opts := []csproto.JSONOption{
			csproto.JSONAllowPartialMessages(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.NoError(t, err, "JSON unmarshaling should not fail since proto3 does not have required fields")
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("enable-all", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGoogleTimestampString(ts)))
		var msg googlev2.EventUsingWKTs
		expected := googlev2.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: googlev2.EventType_EVENT_TYPE_ONE,
		}

		opts := []csproto.JSONOption{
			csproto.JSONAllowPartialMessages(true),
			csproto.JSONAllowUnknownFields(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.NoError(t, err, "JSON unmarshaling should not fail")
		assert.True(t, csproto.Equal(&msg, &expected))
	})
}

func TestProto3GoogleV2MarshalText(t *testing.T) {
	msg := createTestProto3GoogleV2Message()
	// replace the current date/time with a known value for reproducible output
	ts := time.Date(2000, time.January, 1, 1, 2, 3, 0, time.UTC)
	msg.Ts = timestamppb.New(ts)
	// NOTE: the prototext format is explicitly documented as not stable
	// - this string matches google.golang.org/protobuf@v1.28.1
	// - if this test breaks after updating google.golang.org/protobuf, then update the expected string
	//   accordingly
	expected := "name: \"test\"\nlabels: \"one\"\nlabels: \"two\"\nlabels: \"three\"\nembedded: {\n  ID: 42\n  stuff: \"some stuff\"\n  favoriteNumbers: 42\n  favoriteNumbers: 1138\n}\njedi: true\nnested: {\n  details: \"these are some nested details\"\n}\nts: {\n  seconds: 946688523\n}\n"

	s, err := csproto.MarshalText(msg)
	// replace ":  " with ": " to undo the Google library's intentional randomization of the output :(
	// see: https://github.com/protocolbuffers/protobuf-go/blob/v1.28.1/internal/encoding/text/encode.go#L226
	//      https://github.com/protocolbuffers/protobuf-go/blob/v1.28.1/internal/encoding/text/encode.go#L238
	s = strings.ReplaceAll(s, ":  ", ": ")

	assert.NoError(t, err)
	assert.Equal(t, expected, s)
}

func TestProto3GoogleV2Equal(t *testing.T) {
	m1 := createTestProto3GoogleV2Message()
	m2 := createTestProto3GoogleV2Message()
	m2.Ts = timestamppb.New(m1.Ts.AsTime().Add(time.Second))
	// m1 and m2 will have different timestamps so should not be equal
	assert.False(t, csproto.Equal(m1, m2), "messages should not be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	// make them equal
	*m2.Ts = *m1.Ts
	assert.True(t, csproto.Equal(m1, m2), "messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
}

func TestProto3GoogleV2Clone(t *testing.T) {
	m1 := createTestProto3GoogleV2Message()
	m2, ok := csproto.Clone(m1).(*googlev2.TestEvent)

	assert.True(t, ok, "type assertion to *googlev2.TestEvent should succeed")
	assert.True(t, csproto.Equal(m1, m2), "cloned messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	assert.NotEqual(t, unsafe.Pointer(m1), unsafe.Pointer(m2))
}

func TestProto3GoogleV2OneOfs(t *testing.T) {
	// encoded bytes for each test
	// - known timestamp and struct values
	now := timestamppb.New(time.Date(2020, time.January, 1, 1, 2, 3, 4, time.UTC))
	structWithValues, err := structpb.NewStruct(map[string]interface{}{"foo": "bar"})
	require.NoError(t, err)
	require.NotNil(t, structWithValues)
	mapObjectWithValues := &googlev2.MapObject{
		Name:       "test",
		Ts:         now,
		Attributes: map[string]string{"foo": "bar"},
	}

	tests := map[string]struct {
		message any
		data    []byte
	}{
		"zero value": {
			&googlev2.OneOfs{},
			[]byte{},
		},
		"OneOfs_Bools": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Bools{Bools: true}},
			[]byte{0x08, 0x01},
		},
		"OneOfs_Strings": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Strings{Strings: "strings"}},
			[]byte{0x12, 0x07, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73},
		},
		"OneOfs_Int32S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Int32S{Int32S: 2}},
			[]byte{0x18, 0x02},
		},
		"OneOfs_Int64S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Int64S{Int64S: 2}},
			[]byte{0x20, 0x02},
		},
		"OneOfs_Uint32S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Uint32S{Uint32S: 2}},
			[]byte{0x28, 0x02},
		},
		"OneOfs_Uint64S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Uint64S{Uint64S: 2}},
			[]byte{0x30, 0x02},
		},
		"OneOfs_Sint32S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Sint32S{Sint32S: 2}},
			[]byte{0x38, 0x04},
		},
		"OneOfs_Sint64S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Sint64S{Sint64S: 2}},
			[]byte{0x40, 0x04},
		},
		"OneOfs_Fixed32S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Fixed32S{Fixed32S: 2}},
			[]byte{0x4d, 0x02, 0x00, 0x00, 0x00},
		},
		"OneOfs_Fixed64S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Fixed64S{Fixed64S: 2}},
			[]byte{0x51, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		"OneOfs_Sfixed32S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Sfixed32S{Sfixed32S: 2}},
			[]byte{0x5d, 0x02, 0x00, 0x00, 0x00},
		},
		"OneOfs_Sfixed64S": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Sfixed64S{Sfixed64S: 2}},
			[]byte{0x61, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		"OneOfs_Floats": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Floats{Floats: 42.1138}},
			[]byte{0x85, 0x1, 0x88, 0x74, 0x28, 0x42},
		},
		"OneOfs_Doubles": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Doubles{Doubles: 1138.42}},
			[]byte{0x89, 0x1, 0x48, 0xe1, 0x7a, 0x14, 0xae, 0xc9, 0x91, 0x40},
		},
		"OneOfs_Nulls": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Nulls{Nulls: 0}},
			[]byte{0x68, 0x00},
		},
		"OneOfs_Structs": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Structs{Structs: &structpb.Struct{}}},
			[]byte{0x72, 0x00},
		},
		"OneOfs_Structs with values": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Structs{Structs: structWithValues}},
			[]byte{0x72, 0x0e, 0x0a, 0x0c, 0x0a, 0x03, 0x66, 0x6f, 0x6f, 0x12, 0x05, 0x1a, 0x03, 0x62, 0x61, 0x72},
		},
		"OneOfs_Structs when nil": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Structs{Structs: nil}},
			[]byte{0x72, 0x00},
		},
		"OneOfs_Timestamps": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Timestamps{Timestamps: now}},
			[]byte{0x7a, 0x08, 0x08, 0x8b, 0xdf, 0xaf, 0xf0, 0x05, 0x10, 0x04},
		},
		"OneOfs_Timestamps when nil": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Timestamps{Timestamps: nil}},
			[]byte{0x7a, 0x00},
		},
		"OneOfs_Objects": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Objects{Objects: &googlev2.MapObject{}}},
			[]byte{0xf2, 0x01, 0x00},
		},
		"OneOfs_Objects with values": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Objects{Objects: mapObjectWithValues}},
			[]byte{0xf2, 0x1, 0x1c, 0xa, 0x4, 0x74, 0x65, 0x73, 0x74, 0x12, 0x8, 0x8, 0x8b, 0xdf, 0xaf, 0xf0, 0x5, 0x10, 0x4, 0x1a, 0xa, 0xa, 0x3, 0x66, 0x6f, 0x6f, 0x12, 0x3, 0x62, 0x61, 0x72},
		},
		"OneOfs_Objects when nil": {
			&googlev2.OneOfs{Thing: &googlev2.OneOfs_Objects{Objects: nil}},
			[]byte{0xf2, 0x01, 0x00},
		},
	}
	t.Run("marshal", func(t *testing.T) {
		for testName, test := range tests {
			test := test
			t.Run(testName, func(t *testing.T) {
				got, err := csproto.Marshal(test.message)

				require.NoError(t, err)
				require.Equal(t, test.data, got)
			})

		}
	})
	t.Run("unmarshal", func(t *testing.T) {
		for testName, test := range tests {
			test := test
			t.Run(testName, func(t *testing.T) {
				var got googlev2.OneOfs
				require.NoError(t, csproto.Unmarshal(test.data, &got))

				if diff := cmp.Diff(test.message, &got, protocmp.Transform()); diff != "" {
					t.Errorf("unexpected difference:\n%v", diff)
				}
			})
		}
	})
}

func TestProto3GoogleV2Maps(t *testing.T) {
	// known timestamp, struct, and map object values
	now := timestamppb.New(time.Date(2020, time.January, 1, 8, 9, 10, 11, time.UTC))
	structWithValues, err := structpb.NewStruct(map[string]interface{}{"foo": "bar"})
	require.NoError(t, err)
	require.NotNil(t, structWithValues)
	mapObjectWithValues := &googlev2.MapObject{
		Name:       "test",
		Ts:         now,
		Attributes: map[string]string{"foo": "bar"},
	}

	tests := []struct {
		name    string
		message proto.Message
	}{
		{"zero value", &googlev2.Maps{}},
		{"Maps_bools", &googlev2.Maps{Bools: map[string]bool{"one": true, "two": false}}},
		{"Maps_strings", &googlev2.Maps{Strings: map[string]string{"one": "uno", "two": "dos"}}},
		{"Maps_int32s", &googlev2.Maps{Int32S: map[int32]int32{1: 2, 3: 4, -1: -10, math.MaxInt32: math.MinInt32}}},
		{"Maps_int64s", &googlev2.Maps{Int64S: map[int64]int64{1: 2, 3: 4, -1: -10, math.MaxInt64: math.MinInt64}}},
		{"Maps_uint32s", &googlev2.Maps{Uint32S: map[uint32]uint32{1: 2, 3: 4, 0: 0, math.MaxUint32: math.MaxUint32}}},
		{"Maps_uint64s", &googlev2.Maps{Uint64S: map[uint64]uint64{1: 2, 3: 4, 0: 0, math.MaxUint64: math.MaxUint64}}},
		{"Maps_sint32s", &googlev2.Maps{Sint32S: map[int32]int32{1: 2, 3: 4, -1: -10, math.MaxInt32: math.MinInt32}}},
		{"Maps_sint64s", &googlev2.Maps{Sint64S: map[int64]int64{1: 2, 3: 4, -1: -10, math.MaxInt64: math.MinInt64}}},
		{"Maps_fixed32s", &googlev2.Maps{Fixed32S: map[uint32]uint32{1: 2, 3: 4, 0: 0, math.MaxUint32: math.MaxUint32}}},
		{"Maps_fixed64s", &googlev2.Maps{Fixed64S: map[uint64]uint64{1: 2, 3: 4, 0: 0, math.MaxUint64: math.MaxUint64}}},
		{"Maps_sfixed32s", &googlev2.Maps{Sfixed32S: map[int32]int32{1: 2, 3: 4, -1: -10, math.MaxInt32: math.MinInt32}}},
		{"Maps_sfixed64s", &googlev2.Maps{Sfixed64S: map[int64]int64{1: 2, 3: 4, -1: -10, math.MaxInt64: math.MinInt64}}},
		{"Maps_floats", &googlev2.Maps{Floats: map[string]float32{"a": 42.1138}}},
		{"Maps_doubles", &googlev2.Maps{Doubles: map[string]float64{"a": 1138.42}}},
		{"Maps_nulls", &googlev2.Maps{Nulls: map[string]structpb.NullValue{"a": structpb.NullValue_NULL_VALUE}}},
		{"Maps_structs", &googlev2.Maps{Structs: map[string]*structpb.Struct{"a": {}}}},
		{"Maps_structs with values", &googlev2.Maps{Structs: map[string]*structpb.Struct{"a": structWithValues}}},
		{"Maps_structs when nil", &googlev2.Maps{Structs: nil}},
		{"Maps_timestamps", &googlev2.Maps{Timestamps: map[string]*timestamppb.Timestamp{"a": now}}},
		{"Maps_timestamps when nil", &googlev2.Maps{Timestamps: nil}},
		{"Maps_objects", &googlev2.Maps{Objects: map[string]*googlev2.MapObject{"a": {}}}},
		{"Maps_objects with values", &googlev2.Maps{Objects: map[string]*googlev2.MapObject{"a": mapObjectWithValues}}},
		{"Maps_objects when nil", &googlev2.Maps{Objects: nil}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// ordering of map entries is not guaranteed so we just test that a each message correctly
			// round trips through message -> marshal -> unmarshal -> compare
			data, err := csproto.Marshal(test.message)
			require.NoError(t, err)

			var got googlev2.Maps
			require.NoError(t, csproto.Unmarshal(data, &got), "unable to decode.\ndata=%s", func() string {
				var sb strings.Builder
				sb.WriteRune('[')
				for i, b := range data {
					if i > 0 {
						sb.WriteRune(',')
					}
					sb.WriteString(fmt.Sprintf("0x%02x", b))
				}
				sb.WriteRune(']')
				return sb.String()
			}())

			if diff := cmp.Diff(test.message, &got, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference:\n%v", diff)
			}
		})
	}
}

func createTestProto3GoogleV2Message() *googlev2.TestEvent {
	event := googlev2.TestEvent{
		Name:   "test",
		Info:   "",
		Labels: []string{"one", "two", "three"},
		Embedded: &googlev2.EmbeddedEvent{
			ID:              42,
			Stuff:           "some stuff",
			FavoriteNumbers: []int32{42, 1138},
		},
		Path: &googlev2.TestEvent_Jedi{Jedi: true},
		Nested: &googlev2.TestEvent_NestedMsg{
			Details: "these are some nested details",
		},
		Ts: timestamppb.Now(),
	}
	return &event
}
