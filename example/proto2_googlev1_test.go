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
		assert.Equal(t, expected, string(res))
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
