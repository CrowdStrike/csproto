package example_test

import (
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto2/gogo"
)

func TestProto2GogoMessage(t *testing.T) {
	msg := createTestProto2GogoMessage()
	t.Run("gogo_marshal/csproto_unmarshal", func(t *testing.T) {
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
	})
	t.Run("csproto_marshal/gogo_unmarshal", func(t *testing.T) {
		data, err := csproto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using csproto: %v", err)
			t.FailNow()
		}

		var msg2 gogo.BaseEvent
		err = proto.Unmarshal(data, &msg2)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}
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
	}
	testEvent := gogo.TestEvent{
		Name:   proto.String("test"),
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
