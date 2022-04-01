package example_test

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto3/googlev1"
)

func TestProto3GoogleV1Message(t *testing.T) {
	msg := createTestProto3GoogleV1Message()

	t.Run("google_marshal/csproto_unmarshal", func(t *testing.T) {
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

func createTestProto3GoogleV1Message() *googlev1.TestEvent {
	event := googlev1.TestEvent{
		Name:   "test",
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
