package example_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
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
