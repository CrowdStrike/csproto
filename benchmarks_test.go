package csproto_test

import (
	"fmt"
	"testing"

	"github.com/CrowdStrike/csproto"
)

func BenchmarkEncodeString(b *testing.B) {
	var (
		s   = "this is a reasonably long string so that the encoder function has to actually do some work"
		buf = make([]byte, len(s))
	)
	for n := 0; n < b.N; n++ {
		enc := csproto.NewEncoder(buf)
		enc.EncodeString(1, s)
	}
}

func BenchmarkSafeDecodeString(b *testing.B) {
	var (
		// protobuf length-delimited encoding of the string "this is a test"
		d = []byte{0x12, 0xE, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74}

		str string
	)
	dec := csproto.NewDecoder(d)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.Reset()
		_, _, _ = dec.DecodeTag()
		s, _ := dec.DecodeString()

		str = s // use s it's not optimized away
	}
	_ = str
}

func BenchmarkFastDecodeString(b *testing.B) {
	var (
		// protobuf length-delimited encoding of the string "this is a test"
		d = []byte{0x12, 0xE, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74}

		str string
	)
	dec := csproto.NewDecoder(d)
	dec.SetMode(csproto.DecoderModeFast)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.Reset()
		_, _, _ = dec.DecodeTag()
		s, _ := dec.DecodeString()

		str = s // use s it's not optimized away
	}
	_ = str
}

func BenchmarkDecodeFixed32(b *testing.B) {
	var (
		// protobuf encoding of 1138
		d   = []byte{0x25, 0x72, 0x04, 0x00, 0x00}
		val uint32
	)
	dec := csproto.NewDecoder(d)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.Reset()
		_, _, _ = dec.DecodeTag() // consume the tag/wire type
		v, _ := dec.DecodeFixed32()

		val = v
	}
	_ = val
}

func BenchmarkDecodeFixed64(b *testing.B) {
	var (
		// protobuf encoding of 1138
		d   = []byte{0x21, 0x72, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		val uint64
	)
	dec := csproto.NewDecoder(d)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		dec.Reset()
		_, _, _ = dec.DecodeTag() // consume the tag/wire type
		v, _ := dec.DecodeFixed64()

		val = v
	}
	_ = val
}

func BenchmarkDecodeVarint(b *testing.B) {
	cases := []struct {
		name  string
		value uint64
	}{
		{"1byte", 127},
		{"2byte", 300},
		{"3byte", 100000},
		{"4byte", 40000000},
		{"5byte", 5000000000},
		{"8byte", 1 << 55},
		{"10byte", 1<<63 | 1<<62},
	}

	buf := make([]byte, 10)
	for _, tc := range cases {
		n := csproto.EncodeVarint(buf, tc.value)
		encoded := make([]byte, n)
		copy(encoded, buf[:n])

		b.Run(fmt.Sprintf("%s/%d_bytes", tc.name, n), func(b *testing.B) {
			var v uint64
			for i := 0; i < b.N; i++ {
				v, _, _ = csproto.DecodeVarint(encoded)
			}
			_ = v
		})
	}
}
