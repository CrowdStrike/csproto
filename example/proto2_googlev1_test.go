package example_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto2/googlev1"
)

func TestProto2GoogleV1Message(t *testing.T) {
	msg := createTestProto2GoogleV1Message()
	t.Run("google_marshal/csproto_unmarshal", func(t *testing.T) {
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using golang/protobuf: %v", err)
			t.FailNow()
		}

		var msg2 googlev1.BaseEvent
		err = csproto.Unmarshal(data, &msg2)
		if err != nil {
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

		var msg2 googlev1.BaseEvent
		err = proto.Unmarshal(data, &msg2)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}
	})
}

func TestMarshalFailsOnMissingRequiredFieldForGoogleV1Message(t *testing.T) {
	msg := createTestProto2GoogleV1Message()
	msg.EventID = nil

	_, err := csproto.Marshal(msg)
	assert.Error(t, err)
}

func TestUnmarshalFailsOnMissingRequiredFieldForGoogleV1Message(t *testing.T) {
	// encoded contents of a minimal BaseEvent with EventID removed
	data := []byte{
		0x12, 0xb, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0xc3, 0xbc,
		0xdc, 0x92, 0x6, 0x20, 0x1, 0xa2, 0x6, 0x4, 0x2a, 0x2, 0x8, 0x2a,
	}
	var msg googlev1.BaseEvent

	err := csproto.Unmarshal(data, &msg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "one or more required fields missing")
}

func TestProto2GoogleV1MarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		ts := timestamppb.Now()
		etype := googlev1.EventType_EVENT_TYPE_UNDEFINED
		msg := googlev1.EventUsingWKTs{
			Name:      csproto.String("default"),
			Ts:        ts,
			EventType: &etype,
		}
		expected := fmt.Sprintf(`{"eventType":"EVENT_TYPE_UNDEFINED","name":"default","ts":"%s"}`, genGoogleTimestampString(ts))

		res, err := csproto.JSONMarshaler(&msg).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		ts := timestamppb.Now()
		etype := googlev1.EventType_EVENT_TYPE_UNDEFINED
		msg := googlev1.EventUsingWKTs{
			Name:      csproto.String("with-indent"),
			Ts:        ts,
			EventType: &etype,
		}
		expected := fmt.Sprintf("{\n\t\"name\": \"with-indent\",\n\t\"ts\": \"%s\",\n\t\"eventType\": \"EVENT_TYPE_UNDEFINED\"\n}", genGoogleTimestampString(ts))

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
		msg := googlev1.EventUsingWKTs{
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
		etype := googlev1.EventType_EVENT_TYPE_UNDEFINED
		msg := googlev1.EventUsingWKTs{
			Name:      csproto.String("enable-all"),
			EventType: &etype,
		}
		expected := fmt.Sprintf("{\n  \"eventType\":0,\"name\":\"enable-all\",\n  \"ts\":null\n}")

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

func TestProto2GoogleV1MarshalText(t *testing.T) {
	msg := createTestProto2GoogleV1Message()
	// replace the current date/time with a known value for reproducible output
	now := time.Date(2000, time.January, 1, 1, 2, 3, 0, time.UTC)
	msg.Timestamp = proto.Uint64(uint64(now.Unix()))
	// NOTE: the prototext format is explicitly documented as not stable
	// - this string matches github.com/golang/protobuf@v1.5.2
	// - if this test breaks after updating golang/protobuf, then update the expected string
	//   accordingly
	expected := "eventID: \"test-event\"\nsourceID: \"test-source\"\ntimestamp: 946688523\neventType: EVENT_TYPE_ONE\ndata: \"\"\n[crowdstrike.csproto.example.proto2.googlev1.TestEvent.eventExt]: {\n  name: \"test\"\n  info: \"\"\n  labels: \"one\"\n  labels: \"two\"\n  labels: \"three\"\n  embedded: {\n    ID: 42\n    stuff: \"some stuff\"\n    favoriteNumbers: 42\n    favoriteNumbers: 1138\n  }\n  jedi: true\n  nested: {\n    details: \"these are some nested details\"\n  }\n}\n"

	s, err := csproto.MarshalText(msg)
	// replace ":  " with ": " to undo the Google library's intentional randomization of the output :(
	// see: https://github.com/protocolbuffers/protobuf-go/blob/v1.28.1/internal/encoding/text/encode.go#L226
	//      https://github.com/protocolbuffers/protobuf-go/blob/v1.28.1/internal/encoding/text/encode.go#L238
	s = strings.ReplaceAll(s, ":  ", ": ")

	assert.NoError(t, err)
	assert.Equal(t, expected, s)
}

func TestProto2GoogleV1Equal(t *testing.T) {
	m1 := createTestProto2GoogleV1Message()
	m2 := createTestProto2GoogleV1Message()
	*m2.Timestamp = *m1.Timestamp + 1
	// m1 and m2 will have different timestamps so should not be equal
	assert.False(t, csproto.Equal(m1, m2), "messages should not be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
	// make them equal
	*m2.Timestamp = *m1.Timestamp
	assert.True(t, csproto.Equal(m1, m2), "messages should be equal\nm1=%s\nm2=%s", m1.String(), m2.String())
}

func createTestProto2GoogleV1Message() *googlev1.BaseEvent {
	now := uint64(time.Now().UTC().Unix())
	et := googlev1.EventType_EVENT_TYPE_ONE
	baseEvent := googlev1.BaseEvent{
		EventID:   proto.String("test-event"),
		SourceID:  proto.String("test-source"),
		Timestamp: proto.Uint64(now),
		EventType: &et,
		Data:      []byte{},
	}
	testEvent := googlev1.TestEvent{
		Name:   proto.String("test"),
		Info:   proto.String(""),
		Labels: []string{"one", "two", "three"},
		Embedded: &googlev1.EmbeddedEvent{
			ID:              proto.Int32(42),
			Stuff:           proto.String("some stuff"),
			FavoriteNumbers: []int32{42, 1138},
		},
		Path: &googlev1.TestEvent_Jedi{Jedi: true},
		Nested: &googlev1.TestEvent_NestedMsg{
			Details: proto.String("these are some nested details"),
		},
	}
	_ = proto.SetExtension(&baseEvent, googlev1.E_TestEvent_EventExt, &testEvent)
	return &baseEvent
}

func genGoogleTimestampString(ts *timestamppb.Timestamp) string {
	// Uses RFC 3339, where generated output will be Z-normalized and uses 0, 3, 6 or 9 fractional digits.
	// . see the Google's source for reference: https://github.com/protocolbuffers/protobuf-go/blob/v1.28.0/encoding/protojson/well_known_types.go#L782-L806
	t := time.Unix(ts.Seconds, int64(ts.Nanos)).UTC()
	s := t.Format("2006-01-02T15:04:05.000000000")
	s = strings.TrimSuffix(s, "000")
	s = strings.TrimSuffix(s, "000")
	s = strings.TrimSuffix(s, ".000")
	return s + "Z"
}
