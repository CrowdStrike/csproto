package example_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto3/googlev1"
)

func TestProto3GoogleV1Message(t *testing.T) {
	t.Run("google_marshal/csproto_unmarshal", func(t *testing.T) {
		msg := createTestProto3GoogleV1Message()
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using golang/protobuf: %v", err)
			t.FailNow()
		}

		var msg2 googlev1.TestEvent
		if err = csproto.Unmarshal(data, &msg2); err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}
	})
	t.Run("csproto_marshal/google_unmarshal", func(t *testing.T) {
		msg := createTestProto3GoogleV1Message()
		data, err := csproto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using csproto: %v", err)
			t.FailNow()
		}

		var msg2 googlev1.TestEvent
		if err = proto.Unmarshal(data, &msg2); err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}

	})
}

func TestProto3GoogleV1MarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := timestamppb.Now()
		msg := googlev1.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: googlev1.EventType_EVENT_TYPE_ONE,
		}
		expected := fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGoogleTimestampString(ts))

		res, err := csproto.JSONMarshaler(&msg).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		ts := timestamppb.Now()
		msg := googlev1.EventUsingWKTs{
			Name:      "with-indent",
			Ts:        ts,
			EventType: googlev1.EventType_EVENT_TYPE_ONE,
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
		msg := googlev1.EventUsingWKTs{
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
		msg := googlev1.EventUsingWKTs{
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
		etype := googlev1.EventType_EVENT_TYPE_UNDEFINED
		msg := googlev1.EventUsingWKTs{
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

func TestProto3GoogleV1UnmarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGoogleTimestampString(ts)))
		var msg googlev1.EventUsingWKTs
		expected := googlev1.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: googlev1.EventType_EVENT_TYPE_ONE,
		}

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.NoError(t, err)
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("with-unknown-fields", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGoogleTimestampString(ts)))
		var msg googlev1.EventUsingWKTs

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.Error(t, err, "JSON unmarshaling should fail if there are unknown fields")
	})
	t.Run("allow-unknown-fields", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGoogleTimestampString(ts)))
		var msg googlev1.EventUsingWKTs
		expected := googlev1.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: googlev1.EventType_EVENT_TYPE_ONE,
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
		var msg googlev1.EventUsingWKTs
		expected := googlev1.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: googlev1.EventType_EVENT_TYPE_ONE,
		}

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.NoError(t, err, "JSON unmarshaling should not fail since proto3 does not have required fields")
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("allow-partial", func(t *testing.T) {
		ts := timestamppb.Now()
		data := []byte(fmt.Sprintf(`{"ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGoogleTimestampString(ts)))
		var msg googlev1.EventUsingWKTs
		expected := googlev1.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: googlev1.EventType_EVENT_TYPE_ONE,
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
		var msg googlev1.EventUsingWKTs
		expected := googlev1.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: googlev1.EventType_EVENT_TYPE_ONE,
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

func TestProto3GoogleV1MarshalText(t *testing.T) {
	msg := createTestProto3GoogleV1Message()
	// replace the current date/time with a known value for reproducible output
	ts := time.Date(2000, time.January, 1, 1, 2, 3, 0, time.UTC)
	msg.Ts = timestamppb.New(ts)
	// NOTE: the prototext format is explicitly documented as not stable
	// - this string matches github.com/golang/protobuf@v1.5.2
	// - if this test breaks after updating golang/protobuf, then update the expected string
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

func TestProto3GoogleV1Equal(t *testing.T) {
	m1 := createTestProto3GoogleV1Message()
	m2 := createTestProto3GoogleV1Message()
	m2.Ts = timestamppb.New(m1.Ts.AsTime().Add(time.Second))
	// m1 and m2 will have different timestamps so should not be equal
	assert.False(t, csproto.Equal(m1, m2), "messages should not be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	// make them equal
	m2.Ts, _ = csproto.Clone(m1.Ts).(*timestamppb.Timestamp)
	assert.True(t, csproto.Equal(m1, m2), "messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
}

func TestProto3GoogleV1Clone(t *testing.T) {
	m1 := createTestProto3GoogleV1Message()
	m2, ok := csproto.Clone(m1).(*googlev1.TestEvent)

	assert.True(t, ok, "type assertion to *googlev1.TestEvent should succeed")
	assert.True(t, csproto.Equal(m1, m2), "cloned messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	assert.NotEqual(t, unsafe.Pointer(m1), unsafe.Pointer(m2))
}

func createTestProto3GoogleV1Message() *googlev1.TestEvent {
	event := googlev1.TestEvent{
		Name:   "test",
		Info:   "",
		Labels: []string{"one", "two", "three"},
		Embedded: &googlev1.EmbeddedEvent{
			ID:              42,
			Stuff:           "some stuff",
			FavoriteNumbers: []int32{42, 1138},
		},
		Path: &googlev1.TestEvent_Jedi{Jedi: true},
		Nested: &googlev1.TestEvent_NestedMsg{
			Details: "these are some nested details",
		},
		Ts: timestamppb.Now(),
	}
	return &event
}
