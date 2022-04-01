package proto3_test

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/proto3/googlev1"
)

func BenchmarkEncodeGoogleV1(b *testing.B) {
	var (
		evt = createGoogleV1Event()
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
		evt = createGoogleV1Event()
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
		evt  = createGoogleV1Event()
		evt2 googlev1.TestEvent
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
		evt  = createGoogleV1Event()
		evt2 googlev1.TestEvent
	)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		evt2.Reset()
		_ = csproto.Unmarshal(data, &evt2)
	}
}

func createGoogleV1Event() *googlev1.TestEvent {
	event := googlev1.TestEvent{
		Name:      "test-event",
		Info:      "blah blah blah",
		IsAwesome: true,
		Labels:    []string{"one", "two", "three"},
		Embedded: &googlev1.EmbeddedEvent{
			ID:              1,
			FavoriteNumbers: []int32{42, 1138},
			RandomThings: [][]byte{
				{0x0, 0x1, 0x2, 0x3, 0x4, 0x5},
				{0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
			},
		},
		Path: &googlev1.TestEvent_Jedi{
			Jedi: true,
		},
		Ts: timestamppb.Now(),
	}
	return &event
}
