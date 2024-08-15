package example_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"github.com/stretchr/testify/assert"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto2/gogo"
)

func TestProto2GogoMessage(t *testing.T) {
	msgs := []*gogo.BaseEvent{
		createTestProto2GogoAllOptionalMessage(),
		createTestProto2GogoMessage(),
		createTestProto2GogoEmptyExtensionMessage(),
	}
	wrap := func(msg *gogo.BaseEvent) func(t *testing.T) {
		return func(t *testing.T) {
			data, err := proto.Marshal(msg)
			if err != nil {
				t.Errorf("Error marshaling data using gogo/protobuf: %v", err)
				t.FailNow()
			}

			var msg2 gogo.BaseEvent
			err = csproto.Unmarshal(data, &msg2)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			} else if !proto.Equal(msg, &msg2) {
				t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
			}
		}
	}
	for _, msg := range msgs {
		t.Run("gogo_marshal/csproto_unmarshal", wrap(msg))
	}
}

func TestMarshalFailsOnMissingRequiredFieldForGogoMessage(t *testing.T) {
	msg := createTestProto2GogoMessage()
	msg.EventID = nil

	_, err := csproto.Marshal(msg)
	assert.Error(t, err)
}

func TestUnmarshalFailsOnMissingRequiredFieldForGogoMessage(t *testing.T) {
	// encoded contents of a minimal BaseEvent with EventID removed
	data := []byte{
		0x12, 0xb, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0xc3, 0xbc,
		0xdc, 0x92, 0x6, 0x20, 0x1, 0xa2, 0x6, 0x4, 0x2a, 0x2, 0x8, 0x2a,
	}
	var msg gogo.BaseEvent

	err := csproto.Unmarshal(data, &msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "one or more required fields missing")
}

func TestProto2GogoMarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := types.TimestampNow()
		etype := gogo.EventType_EVENT_TYPE_UNDEFINED
		msg := gogo.EventUsingWKTs{
			Name:      csproto.String("default"),
			Ts:        ts,
			EventType: &etype,
		}
		expected := fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","name":"default","ts":"%s"}`, genGogoTimestampString(ts))

		res, err := csproto.JSONMarshaler(&msg).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		ts := types.TimestampNow()
		etype := gogo.EventType_EVENT_TYPE_UNDEFINED
		msg := gogo.EventUsingWKTs{
			Name:      csproto.String("with-indent"),
			Ts:        ts,
			EventType: &etype,
		}
		expected := fmt.Sprintf("{\n\t\"name\": \"with-indent\",\n\t\"ts\": \"%s\",\n\t\"eventType\": \"EVENT_TYPE_UNDEFINED\"\n}", genGogoTimestampString(ts))

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
			Name: csproto.String("exclude-zero-values"),
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
			Name: csproto.String("include-zero-values"),
		}
		expected := `{"eventType":null,"name":"include-zero-values","ts":null}`

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
			Name:      csproto.String("enable-all"),
			EventType: &etype,
		}
		expected := "{\n  \"eventType\":0,\"name\":\"enable-all\",\n  \"ts\":null\n}"

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

func TestProto2GogoV1UnmarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","name":"default","ts":"%s"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.NoError(t, err)
		etype := gogo.EventType_EVENT_TYPE_UNDEFINED
		expected := gogo.EventUsingWKTs{
			Name:      csproto.String("default"),
			Ts:        ts,
			EventType: &etype,
		}
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("with-unknown-fields", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","name":"default","ts":"%s","fdsajkld":"dfjakldfa"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.Error(t, err, "JSON unmarshaling should fail if there are unknown fields")
	})
	t.Run("allow-unknown-fields", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","name":"default","ts":"%s","fdsajkld":"dfjakldfa"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs

		opts := []csproto.JSONOption{
			csproto.JSONAllowUnknownFields(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.NoError(t, err)
		etype := gogo.EventType_EVENT_TYPE_UNDEFINED
		expected := gogo.EventUsingWKTs{
			Name:      csproto.String("default"),
			Ts:        ts,
			EventType: &etype,
		}
		assert.True(t, csproto.Equal(&msg, &expected))
	})
	t.Run("with-missing-required-field", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","ts":"%s"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs

		err := csproto.JSONUnmarshaler(&msg).UnmarshalJSON(data)
		assert.Error(t, err, "JSON unmarshaling should fail if required fields are missing")
	})
	t.Run("allow-partial", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","ts":"%s"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs

		opts := []csproto.JSONOption{
			csproto.JSONAllowPartialMessages(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.Error(t, err, "JSONAllowPartialMessages(true) should have no effect on Gogo messages")
	})
	t.Run("enable-all", func(t *testing.T) {
		ts := types.TimestampNow()
		data := []byte(fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","ts":"%s","fdsajkld":"dfjakldfa"}`, genGogoTimestampString(ts)))
		var msg gogo.EventUsingWKTs

		opts := []csproto.JSONOption{
			csproto.JSONAllowUnknownFields(true),
			csproto.JSONAllowPartialMessages(true),
		}
		err := csproto.JSONUnmarshaler(&msg, opts...).UnmarshalJSON(data)
		assert.Error(t, err, "JSONAllowPartialMessages(true) should have no effect on Gogo messages")
	})
}

func TestProto2GogoMarshalText(t *testing.T) {
	msg := createTestProto2GogoMessage()
	// replace the current date/time with a known value for reproducible output
	now := time.Date(2000, time.January, 1, 1, 2, 3, 0, time.UTC)
	msg.Timestamp = proto.Uint64(uint64(now.Unix()))
	// NOTE: the prototext format is explicitly documented as not stable
	// - this string matches gogo/protobuf@v1.3.2
	// - if this test breaks after updating gogo/protobuf, then update the expected string
	//   accordingly
	expected := `eventID: "test-event"
sourceID: "test-source"
timestamp: 946688523
eventType: EVENT_TYPE_ONE
data: ""
[crowdstrike.csproto.example.proto2.gogo.TestEvent.eventExt]: <
  name: "test"
  info: ""
  labels: "one"
  labels: "two"
  labels: "three"
  embedded: <
    ID: 42
    stuff: "some stuff"
    favoriteNumbers: 42
    favoriteNumbers: 1138
  >
  jedi: true
  nested: <
    details: "these are some nested details"
  >
>
`

	s, err := csproto.MarshalText(msg)

	assert.NoError(t, err)
	assert.Equal(t, expected, s)
}

func TestProto2GogoEqual(t *testing.T) {
	m1 := createTestProto2GogoMessage()
	m2 := createTestProto2GogoMessage()
	*m2.Timestamp = *m1.Timestamp + 1
	// m1 and m2 will have different timestamps so should not be equal
	assert.False(t, csproto.Equal(m1, m2), "messages should not be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	// make them equal
	*m2.Timestamp = *m1.Timestamp
	assert.True(t, csproto.Equal(m1, m2), "messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
}

func TestProto2GogoClone(t *testing.T) {
	m1 := createTestProto2GogoMessage()
	m2, ok := csproto.Clone(m1).(*gogo.BaseEvent)

	assert.True(t, ok, "type assertion to *gogo.BaseEvent should succeed")
	assert.True(t, csproto.Equal(m1, m2), "cloned messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	assert.NotEqual(t, unsafe.Pointer(m1), unsafe.Pointer(m2))
}

func TestProto2GogoExtensionFieldNumber(t *testing.T) {
	n, err := csproto.ExtensionFieldNumber(gogo.E_TestEvent_EventExt)
	assert.Equal(t, 100, n, "extension field number should be 100")
	assert.NoError(t, err)

	n, err = csproto.ExtensionFieldNumber(37)
	assert.Equal(t, 0, n, "field number should be 0 for invalid value")
	assert.Error(t, err)
}

func TestProto2GogoExtensions(t *testing.T) {
	m := createTestProto2GogoMessage()
	has := csproto.HasExtension(m, gogo.E_TestEvent_EventExt)
	assert.True(t, has)

	csproto.ClearExtension(m, gogo.E_TestEvent_EventExt)
	has = csproto.HasExtension(m, gogo.E_TestEvent_EventExt)
	assert.False(t, has)

	m2 := gogo.AllOptionalFields{}
	err := csproto.SetExtension(m, gogo.E_TestEvent_EventExt, &m2)
	assert.Error(t, err)
}

func TestProto2GogoRangeExtensions(t *testing.T) {
	m := createTestProto2GogoMessage()
	t.Run("enumerate all", func(t *testing.T) {
		nCalls := 0
		err := csproto.RangeExtensions(m, func(value interface{}, name string, field int32) error {
			t.Logf("name=%s, field=%d, value=%v", name, field, value)
			nCalls++
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, nCalls, "range callback should have been called 1 time")
	})
	t.Run("enumeration error", func(t *testing.T) {
		var (
			testErr = fmt.Errorf("something went wrong")
			nCalls  = 0
		)
		err := csproto.RangeExtensions(m, func(value interface{}, name string, field int32) error {
			nCalls++
			return testErr
		})

		assert.Error(t, err)
		assert.Equal(t, testErr, err)
		assert.Equal(t, 1, nCalls, "range callback should have been called 1 time")
	})
}

func createTestProto2GogoMessage() *gogo.BaseEvent {
	now := uint64(time.Now().UTC().Unix())
	et := gogo.EventType_EVENT_TYPE_ONE
	baseEvent := gogo.BaseEvent{
		EventID:   proto.String("test-event"),
		SourceID:  proto.String("test-source"),
		Timestamp: proto.Uint64(now),
		EventType: &et,
		Data:      []byte{},
	}
	testEvent := gogo.TestEvent{
		Name:   proto.String("test"),
		Info:   proto.String(""),
		Labels: []string{"one", "two", "three"},
		Embedded: &gogo.EmbeddedEvent{
			ID:              proto.Int32(42),
			Stuff:           proto.String("some stuff"),
			FavoriteNumbers: []int32{42, 1138},
		},
		Path: &gogo.TestEvent_Jedi{Jedi: true},
		Nested: &gogo.TestEvent_NestedMsg{
			Details: proto.String("these are some nested details"),
		},
	}
	_ = proto.SetExtension(&baseEvent, gogo.E_TestEvent_EventExt, &testEvent)
	return &baseEvent
}

func createTestProto2GogoAllOptionalMessage() *gogo.BaseEvent {
	now := uint64(time.Now().UTC().Unix())
	et := gogo.EventType_EVENT_TYPE_ONE
	baseEvent := gogo.BaseEvent{
		EventID:   proto.String("test-event"),
		SourceID:  proto.String("test-source"),
		Timestamp: proto.Uint64(now),
		EventType: &et,
		Data:      []byte{},
	}
	testEvent := gogo.AllOptionalFields{}
	_ = proto.SetExtension(&baseEvent, gogo.E_AllOptionalFields_EventExt, &testEvent)
	return &baseEvent
}

func createTestProto2GogoEmptyExtensionMessage() *gogo.BaseEvent {
	now := uint64(time.Now().UTC().Unix())
	et := gogo.EventType_EVENT_TYPE_ONE
	baseEvent := gogo.BaseEvent{
		EventID:   proto.String("test-event"),
		SourceID:  proto.String("test-source"),
		Timestamp: proto.Uint64(now),
		EventType: &et,
		Data:      []byte{},
	}
	testEvent := gogo.AllOptionalFields{
		Field1: proto.String("test"),
	}
	emptyEventExt := gogo.EmptyExtension{}
	_ = proto.SetExtension(&testEvent, gogo.E_EmptyExtension_EventExt, &emptyEventExt)
	_ = proto.SetExtension(&baseEvent, gogo.E_AllOptionalFields_EventExt, &testEvent)
	return &baseEvent
}

func genGogoTimestampString(ts *types.Timestamp) string {
	// Uses RFC 3339, where generated output will be Z-normalized and uses 0, 3, 6 or 9 fractional digits.
	// . see the Google's source for reference: https://github.com/protocolbuffers/protobuf-go/blob/v1.28.0/encoding/protojson/well_known_types.go#L782-L806
	t := time.Unix(ts.Seconds, int64(ts.Nanos)).UTC()
	s := t.Format("2006-01-02T15:04:05.000000000")
	s = strings.TrimSuffix(s, "000")
	s = strings.TrimSuffix(s, "000")
	s = strings.TrimSuffix(s, ".000")
	return s + "Z"
}
