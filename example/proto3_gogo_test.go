package example_test

import (
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"

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

func createTestProto3GogoMessage() *gogo.TestEvent {
	event := gogo.TestEvent{
		Name:   "test",
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
