package proto3_test

import (
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto3/gogo"
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
		evt2 gogo.TestEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = proto.Unmarshal(data, &evt2)
	}
}

func BenchmarkCustomDecodeGogo(b *testing.B) {
	var (
		evt  = createGogoEvent()
		evt2 gogo.TestEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = csproto.Unmarshal(data, &evt2)
	}
}

func createGogoEvent() *gogo.TestEvent {
	event := gogo.TestEvent{
		Name:      "test-event",
		Info:      "blah blah blah",
		IsAwesome: true,
		Labels:    []string{"one", "two", "three"},
		Embedded: &gogo.EmbeddedEvent{
			ID:              1,
			FavoriteNumbers: []int32{42, 1138},
			RandomThings: [][]byte{
				{0x0, 0x1, 0x2, 0x3, 0x4, 0x5},
				{0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
			},
		},
		Path: &gogo.TestEvent_Jedi{
			Jedi: true,
		},
		Ts: types.TimestampNow(),
	}
	return &event
}
