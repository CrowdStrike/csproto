package example_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto2/googlev2"
)

func TestProto2GoogleV2Message(t *testing.T) {
	msg := createTestProto2GoogleV2Message()
	t.Run("google_marshal/csproto_unmarshal", func(t *testing.T) {
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Errorf("Error marshaling data using golang/protobuf: %v", err)
			t.FailNow()
		}

		var msg2 googlev2.BaseEvent
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

		var msg2 googlev2.BaseEvent
		err = proto.Unmarshal(data, &msg2)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		} else if !proto.Equal(msg, &msg2) {
			t.Errorf("Mismatched data after unmarshal\n\tExpected: %s\n\t     Got: %s\n", msg.String(), msg2.String())
		}
	})
}

func createTestProto2GoogleV2Message() *googlev2.BaseEvent {
	now := uint64(time.Now().UTC().Unix())
	et := googlev2.EventType_EVENT_TYPE_ONE
	baseEvent := googlev2.BaseEvent{
		EventID:   proto.String("test-event"),
		SourceID:  proto.String("test-source"),
		Timestamp: proto.Uint64(now),
		EventType: &et,
	}
	testEvent := googlev2.TestEvent{
		Name:   proto.String("test"),
		Labels: []string{"one", "two", "three"},
		Embedded: &googlev2.EmbeddedEvent{
			ID:              proto.Int32(42),
			Stuff:           proto.String("some stuff"),
			FavoriteNumbers: []int32{42, 1138},
		},
		Path: &googlev2.TestEvent_Jedi{Jedi: true},
		Nested: &googlev2.TestEvent_NestedMsg{
			Details: proto.String("these are some nested details"),
		},
	}
	proto.SetExtension(&baseEvent, googlev2.E_TestEvent_EventExt, &testEvent)
	return &baseEvent
}
