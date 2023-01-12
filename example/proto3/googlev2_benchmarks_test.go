package proto3_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto3/googlev2"
	"github.com/CrowdStrike/csproto/lazyproto"
)

func BenchmarkEncodeGoogleV2(b *testing.B) {
	var (
		evt = createGoogleV2Event()
		buf []byte
	)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf, _ = proto.Marshal(evt)
		_ = buf
	}
	_ = buf
}

func BenchmarkCustomEncodeGoogleV2(b *testing.B) {
	var (
		evt = createGoogleV2Event()
		buf []byte
	)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		buf, _ = csproto.Marshal(evt)
		_ = buf
	}
	_ = buf
}

func BenchmarkDecodeGoogleV2(b *testing.B) {
	var (
		evt  = createGoogleV2Event()
		evt2 googlev2.TestEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = proto.Unmarshal(data, &evt2)
	}
}

func BenchmarkCustomDecodeGoogleV2(b *testing.B) {
	var (
		evt  = createGoogleV2Event()
		evt2 googlev2.TestEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = csproto.Unmarshal(data, &evt2)
	}
}

func BenchmarkLazyDecodeGoogleV2(b *testing.B) {
	var (
		evt = createGoogleV2Event()
		def = lazyproto.NewDef(1)
	)
	_ = def.NestedTag(5, 1)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		r, _ := lazyproto.Decode(data, def)
		_ = r.Close()
	}
}

func createGoogleV2Event() *googlev2.TestEvent {
	event := googlev2.TestEvent{
		Name:      "test-event",
		Info:      "blah blah blah",
		IsAwesome: true,
		Labels:    []string{"one", "two", "three"},
		Embedded: &googlev2.EmbeddedEvent{
			ID:              1,
			FavoriteNumbers: []int32{42, 1138},
			RandomThings: [][]byte{
				{0x0, 0x1, 0x2, 0x3, 0x4, 0x5},
				{0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
			},
		},
		Path: &googlev2.TestEvent_Jedi{
			Jedi: true,
		},
		Ts: timestamppb.Now(),
	}
	return &event
}
