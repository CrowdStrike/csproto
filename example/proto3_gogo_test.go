package example_test

import (
	"fmt"
	"testing"

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
