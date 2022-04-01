package proto2_test

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/gogo/protobuf/proto"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto2/gogo"
)

func BenchmarkEncodeGogo(b *testing.B) {
	var (
		evt = createGogoEvent()
		buf []byte
	)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf, _ = proto.Marshal(evt)
		_ = buf
	}
	_ = buf
}

func BenchmarkCustomEncodeGogo(b *testing.B) {
	var (
		evt = createGogoEvent()
		buf []byte
	)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf, _ = csproto.Marshal(evt)
		_ = buf
	}
	_ = buf
}

func BenchmarkDecodeGogo(b *testing.B) {
	var (
		evt  = createGogoEvent()
		evt2 gogo.BaseEvent
		ext  *gogo.TestEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = proto.Unmarshal(data, &evt2)
		// also extract the proto2 extension to ensure we fully unmarshal *all* the data
		extval, _ := proto.GetExtension(&evt2, gogo.E_TestEvent_EventExt)
		ext = extval.(*gogo.TestEvent)
	}
	_ = ext
}

func BenchmarkCustomDecodeGogo(b *testing.B) {
	var (
		evt  = createGogoEvent()
		evt2 gogo.BaseEvent
		ext  *gogo.TestEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = csproto.Unmarshal(data, &evt2)
		// also extract the proto2 extension to ensure we fully unmarshal *all* the data
		extval, _ := csproto.GetExtension(&evt2, gogo.E_TestEvent_EventExt)
		ext = extval.(*gogo.TestEvent)
	}
	_ = ext
}

func createGogoEvent() *gogo.BaseEvent {
	eventType := gogo.EventType_EVENT_TYPE_ONE
	baseEvent := gogo.BaseEvent{
		EventID:   csproto.String(uuid.Must(uuid.NewV4()).String()),
		SourceID:  csproto.String(uuid.Must(uuid.NewV4()).String()),
		Timestamp: csproto.Uint64(uint64(time.Now().UTC().Unix())),
		EventType: &eventType,
	}
	extEvent := gogo.TestEvent{
		Name:      csproto.String("test-event"),
		Info:      csproto.String("blah blah blah"),
		IsAwesome: csproto.Bool(true),
		Labels:    []string{"one", "two", "three"},
		Embedded: &gogo.EmbeddedEvent{
			ID:              csproto.Int32(1),
			FavoriteNumbers: []int32{42, 1138},
			RandomThings: [][]byte{
				{0x0, 0x1, 0x2, 0x3, 0x4, 0x5},
				{0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
			},
		},
		Path: &gogo.TestEvent_Jedi{
			Jedi: true,
		},
	}
	_ = csproto.SetExtension(&baseEvent, gogo.E_TestEvent_EventExt, &extEvent)
	return &baseEvent
}
