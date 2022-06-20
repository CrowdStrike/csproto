package example_test

import (
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
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
			}
			// force decoding of proto2 extension data
			_, _ = csproto.GetExtension(&msg2, gogo.E_TestEvent_EventExt)
			_, _ = csproto.GetExtension(&msg2, gogo.E_AllOptionalFields_EventExt)
			_, _ = csproto.GetExtension(&msg2, gogo.E_EmptyExtension_EventExt)
			if !proto.Equal(msg, &msg2) {
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
