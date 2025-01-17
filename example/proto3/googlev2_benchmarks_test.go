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
	_ = def.NestedTag(5, 1, 2, 3, 4)
	data, _ := proto.Marshal(evt)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		r, _ := lazyproto.Decode(data, def) //nolint: staticcheck // benchmarking deprecated function to demonstrate the difference
		_ = r.Close()
	}
}

func BenchmarkLazyDecoder(b *testing.B) {
	var (
		evt = createGoogleV2Event()
		def = lazyproto.NewDef(1, 2, 3, 4, 5, 6, 7, 8, 9)
	)
	_ = def.NestedTag(5, 1, 2, 3, 4)
	data, _ := proto.Marshal(evt)
	b.Run("safe", func(b *testing.B) {
		dec, _ := lazyproto.NewDecoder(def)
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			r, _ := dec.Decode(data)
			discardStrings, _ = r.StringValues(4)
			_ = r.Close()
		}
	})

	b.Run("unsafe", func(b *testing.B) {
		dec, _ := lazyproto.NewDecoder(def, lazyproto.WithMode(csproto.DecoderModeFast))
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			r, _ := dec.Decode(data)
			discardStrings, _ = r.StringValues(4)
			_ = r.Close()
		}
	})
}

var discardStrings []string

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
