package example_test

import (
	"fmt"
	"testing"
	"time"
	"unsafe"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/stretchr/testify/assert"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto3/gogo"
)

func TestProto3GogoMessage(t *testing.T) {
	msg := createTestProto3GogoMessage()

	t.Run("gogo_marshal/csproto_unmarshal", func(t *testing.T) {
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using gogo/protobuf: %v", err)
			t.FailNow()
		}

		var msg2 gogo.TestEvent
		if err = csproto.Unmarshal(data, &msg2); err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}
	})
	t.Run("csproto_marshal/gogo_unmarshal", func(t *testing.T) {
		data, err := csproto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using csproto: %v", err)
			t.FailNow()
		}

		var msg2 gogo.TestEvent
		if err = proto.Unmarshal(data, &msg2); err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}

	})
}

func TestProto3GogoMarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := types.TimestampNow()
		msg := gogo.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: gogo.EventType_EVENT_TYPE_ONE,
		}
		expected := fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGogoTimestampString(ts))

		res, err := csproto.JSONMarshaler(&msg).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		ts := types.TimestampNow()
		msg := gogo.EventUsingWKTs{
			Name:      "with-indent",
			Ts:        ts,
			EventType: gogo.EventType_EVENT_TYPE_ONE,
		}
		expected := fmt.Sprintf("{\n\t\"name\": \"with-indent\",\n\t\"ts\": \"%s\",\n\t\"eventType\": \"EVENT_TYPE_ONE\"\n}", genGogoTimestampString(ts))

		opts := []csproto.JSONOption{
			csproto.JSONIndent("\t"),
		}
		res, err := csproto.JSONMarshaler(&msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
		// compare the actual string
		// - validate the formatted JSON text output, including line breaks and indentation
		assert.Equal(t, expected, string(res))
	})
	t.Run("exclude-zero-values", func(t *testing.T) {
		msg := gogo.EventUsingWKTs{
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
		msg := gogo.EventUsingWKTs{
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
		etype := gogo.EventType_EVENT_TYPE_UNDEFINED
		msg := gogo.EventUsingWKTs{
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

func TestProto3GogoUnmarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs
		expected := gogo.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: gogo.EventType_EVENT_TYPE_ONE,
		}

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.NoError(t, err)
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("with-unknown-fields", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.Error(t, err, "JSON unmarshaling should fail if there are unknown fields")
	})
	t.Run("allow-unknown-fields", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"name":"default","ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs
		expected := gogo.EventUsingWKTs{
			Name:      "default",
			Ts:        ts,
			EventType: gogo.EventType_EVENT_TYPE_ONE,
		}

		opts := []csproto.JSONOption{
			csproto.JSONAllowUnknownFields(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.NoError(t, err)
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("with-missing-required-fields", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs
		expected := gogo.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: gogo.EventType_EVENT_TYPE_ONE,
		}

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.NoError(t, err, "JSON unmarshaling should not fail since proto3 does not have required fields")
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("allow-partial", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"ts":"%s","eventType":"EVENT_TYPE_ONE"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs
		expected := gogo.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: gogo.EventType_EVENT_TYPE_ONE,
		}

		opts := []csproto.JSONOption{
			csproto.JSONAllowPartialMessages(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.NoError(t, err, "JSON unmarshaling should not fail since proto3 does not have required fields")
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("enable-all", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"ts":"%s","eventType":"EVENT_TYPE_ONE","dfjaklds":"dfjklad"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs
		expected := gogo.EventUsingWKTs{
			Name:      "", // name should not be set
			Ts:        ts,
			EventType: gogo.EventType_EVENT_TYPE_ONE,
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

func TestProto3GogoMarshalText(t *testing.T) {
	msg := createTestProto3GogoMessage()
	// replace the current date/time with a known value for reproducible output
	now := time.Date(2000, time.January, 1, 1, 2, 3, 0, time.UTC)
	msg.Ts, _ = types.TimestampProto(now)
	// NOTE: the prototext format is explicitly documented as not stable
	// - this string matches gogo/protobuf@v1.3.2
	// - if this test breaks after updating gogo/protobuf, then update the expected string
	//   accordingly
	expected := "name: \"test\"\nlabels: \"one\"\nlabels: \"two\"\nlabels: \"three\"\nembedded: <\n  ID: 42\n  stuff: \"some stuff\"\n  favoriteNumbers: 42\n  favoriteNumbers: 1138\n>\njedi: true\nnested: <\n  details: \"these are some nested details\"\n>\nts: <\n  seconds: 946688523\n>\n"

	s, err := csproto.MarshalText(msg)

	assert.NoError(t, err)
	assert.Equal(t, expected, s)
}

func TestProto3GogoEqual(t *testing.T) {
	m1 := createTestProto3GogoMessage()
	m2 := createTestProto3GogoMessage()
	// m1 and m2 will have different timestamps so should not be equal
	assert.False(t, csproto.Equal(m1, m2), "messages should not be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	// make them equal
	*m2.Ts = *m1.Ts
	assert.True(t, csproto.Equal(m1, m2), "messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
}

func TestProto3GogoClone(t *testing.T) {
	m1 := createTestProto3GogoMessage()
	m2, ok := csproto.Clone(m1).(*gogo.TestEvent)

	assert.True(t, ok, "type assertion to *gogo.TestEvent should succeed")
	assert.True(t, csproto.Equal(m1, m2), "cloned messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	assert.NotEqual(t, unsafe.Pointer(m1), unsafe.Pointer(m2))
}

func createTestProto3GogoMessage() *gogo.TestEvent {
	event := gogo.TestEvent{
		Name:   "test",
		Info:   "",
		Labels: []string{"one", "two", "three"},
		Embedded: &gogo.EmbeddedEvent{
			ID:              42,
			Stuff:           "some stuff",
			FavoriteNumbers: []int32{42, 1138},
		},
		Path: &gogo.TestEvent_Jedi{Jedi: true},
		Nested: &gogo.TestEvent_NestedMsg{
			Details: "these are some nested details",
		},
		Ts: types.TimestampNow(),
	}
	return &event
}
