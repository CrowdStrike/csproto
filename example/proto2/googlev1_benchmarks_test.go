package proto2_test

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto2/googlev1"
)

func BenchmarkEncodeGoogleV1(b *testing.B) {
	var (
		evt = createGoogleV1Event(b)
		buf []byte
	)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf, _ = proto.Marshal(evt)
		_ = buf
	}
	_ = buf
}

func BenchmarkCustomEncodeGoogleV1(b *testing.B) {
	var (
		evt = createGoogleV1Event(b)
		buf []byte
	)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf, _ = csproto.Marshal(evt)
		_ = buf
	}
	_ = buf
}

func BenchmarkDecodeGoogleV1(b *testing.B) {
	var (
		evt  = createGoogleV1Event(b)
		evt2 googlev1.BaseEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = proto.Unmarshal(data, &evt2)
	}
}

func BenchmarkCustomDecodeGoogleV1(b *testing.B) {
	var (
		evt  = createGoogleV1Event(b)
		evt2 googlev1.BaseEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = csproto.Unmarshal(data, &evt2)
	}
}

func createGoogleV1Event(t interface{ Errorf(string, ...interface{}) }) *googlev1.BaseEvent {
	eventType := googlev1.EventType_EVENT_TYPE_ONE
	baseEvent := googlev1.BaseEvent{
		EventID:   csproto.String(uuid.Must(uuid.NewV4()).String()),
		SourceID:  csproto.String(uuid.Must(uuid.NewV4()).String()),
		Timestamp: csproto.Uint64(uint64(time.Now().UTC().Unix())),
		EventType: &eventType,
	}
	extEvent := googlev1.TestEvent{
		Name:      csproto.String("test-event"),
		Info:      csproto.String("blah blah blah"),
		IsAwesome: csproto.Bool(true),
		Labels:    []string{"one", "two", "three"},
		Embedded: &googlev1.EmbeddedEvent{
			ID:              csproto.Int32(1),
			FavoriteNumbers: []int32{42, 1138},
			RandomThings: [][]byte{
				{0x0, 0x1, 0x2, 0x3, 0x4, 0x5},
				{0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
			},
		},
		Path: &googlev1.TestEvent_Jedi{
			Jedi: true,
		},
	}
	if err := csproto.SetExtension(&baseEvent, googlev1.E_TestEvent_EventExt, &extEvent); err != nil {
		t.Errorf("unable to set proto2 extension: %v", err)
	}
	return &baseEvent
}
