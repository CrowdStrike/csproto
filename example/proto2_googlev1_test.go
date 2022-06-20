package example_test

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"

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
		}
		// verify decoding of proto2 extension data
		xd, err := csproto.GetExtension(&msg2, googlev1.E_TestEvent_EventExt)
		if err != nil {
			t.Errorf("Unable to read proto2 extension data: %v", err)
		}
		if xd == nil || reflect.ValueOf(xd).IsNil() {
			t.Errorf("Unable to read proto2 extension data: result is nil")
		}
		fmt.Fprintf(os.Stderr, "extension data: %#v", xd)
		if !proto.Equal(msg, &msg2) {
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
