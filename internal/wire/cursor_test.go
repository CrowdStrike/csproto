package wire_test

import (
	"errors"
	"io"
	"math"
	"strconv"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/internal/wire"
)

// newCursor returns a Cursor over p, failing the test if NewCursor errors.
func newCursor(t testing.TB, p []byte) wire.Cursor {
	t.Helper()
	c, err := wire.NewCursor(p)
	require.NoError(t, err)
	return c
}

// ---------- helpers ----------

// encTag encodes a protobuf tag key (field_number << 3 | wire_type) as a varint.
func encTag(tag int, wt csproto.WireType) []byte {
	var buf [10]byte
	n := csproto.EncodeTag(buf[:], tag, wt)
	return buf[:n]
}

// encVarint encodes v as a base-128 varint.
func encVarint(v uint64) []byte {
	var buf [10]byte
	n := csproto.EncodeVarint(buf[:], v)
	return buf[:n]
}

// concat concatenates byte slices.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---------- NextShortTag ----------

// TestNextShortTagMatchesNextTag checks NextShortTag exhaustively against
// NextTag for every 1-byte input, every 2-byte input, and every 2-byte prefix
// followed by a third byte. It must either agree with NextTag exactly or
// decline (tag == 0) without moving the cursor, and it must not decline any
// key of 1 or 2 bytes that NextTag accepts.
func TestNextShortTagMatchesNextTag(t *testing.T) {
	t.Parallel()

	check := func(data []byte) {
		c := newCursor(t, data)
		short, sTag, sWT := c.NextShortTag()
		full, fTag, fWT, fErr := c.NextTag()
		if sTag == 0 {
			if short.Offset() != 0 {
				t.Fatalf("% x: declined but moved the cursor to %d", data, short.Offset())
			}
			if fErr == nil && full.Offset() <= 2 {
				t.Fatalf("% x: declined a %d-byte key that NextTag accepts (tag %d)", data, full.Offset(), fTag)
			}
			return
		}
		if fErr != nil {
			t.Fatalf("% x: NextShortTag accepted tag %d, NextTag failed: %v", data, sTag, fErr)
		}
		if sTag != fTag || sWT != fWT || short.Offset() != full.Offset() {
			t.Fatalf("% x: NextShortTag=(%d, %v, @%d) NextTag=(%d, %v, @%d)",
				data, sTag, sWT, short.Offset(), fTag, fWT, full.Offset())
		}
	}

	for b0 := range 256 {
		check([]byte{byte(b0)})
		for b1 := range 256 {
			check([]byte{byte(b0), byte(b1)})
			check([]byte{byte(b0), byte(b1), 0x01})
		}
	}
}

// TestNextShortTagFullRange walks the entire accepted range of NextShortTag by
// field number — every field 1-2047 crossed with every wire type 0-7 — and
// checks each result against the expected (tag, wire type, key length) rather
// than against NextTag. Each key is decoded from offset 0 with nothing after
// it, and from mid-buffer between 0xff guard bytes (unterminated continuation
// bytes that would corrupt the result if read). It also pins both edges of the
// range: field 0 and field 2048+ (3-byte keys) must be declined, as must
// truncated 2-byte keys, while zero-padded 2-byte forms of 1-byte keys are
// accepted.
func TestNextShortTagFullRange(t *testing.T) {
	t.Parallel()

	guard := repeatByte(0xff, 3)

	// accept asserts NextShortTag decodes key (embedded at every position
	// variant) as (wantTag, wantWT), consuming exactly len(key) bytes, and
	// agrees with NextTag and csproto.Decoder.DecodeTag.
	accept := func(t *testing.T, key []byte, wantTag int, wantWT csproto.WireType) {
		t.Helper()
		for _, v := range []struct {
			name  string
			data  []byte
			start int
		}{
			{"exact", key, 0},
			{"mid-buffer", concat(guard, key, guard), len(guard)},
		} {
			c := newCursor(t, v.data).Seek(v.start)
			next, tag, wt := c.NextShortTag()
			if tag != wantTag || wt != wantWT || next.Offset() != v.start+len(key) {
				t.Fatalf("% x (%s): got (%d, %d, @%d), want (%d, %d, @%d)",
					key, v.name, tag, wt, next.Offset(), wantTag, wantWT, v.start+len(key))
			}
			if c.Offset() != v.start {
				t.Fatalf("% x (%s): receiver mutated to @%d", key, v.name, c.Offset())
			}
			full, fTag, fWT, fErr := c.NextTag()
			if fErr != nil || fTag != tag || fWT != wt || full.Offset() != next.Offset() {
				t.Fatalf("% x (%s): NextTag=(%d, %d, @%d, %v) disagrees", key, v.name, fTag, fWT, full.Offset(), fErr)
			}
		}
		dTag, dWT, dErr := csproto.NewDecoder(key).DecodeTag()
		if dErr != nil || dTag != wantTag || dWT != wantWT {
			t.Fatalf("% x: csproto.Decoder=(%d, %d, %v) disagrees", key, dTag, dWT, dErr)
		}
	}

	// decline asserts NextShortTag returns tag 0 and leaves the cursor where
	// it started, at every position variant.
	decline := func(t *testing.T, key []byte) {
		t.Helper()
		for _, v := range []struct {
			name  string
			data  []byte
			start int
		}{
			{"exact", key, 0},
			{"mid-buffer", concat(guard, key), len(guard)}, // no trailing guard: truncation must stay truncation
		} {
			c := newCursor(t, v.data).Seek(v.start)
			next, tag, wt := c.NextShortTag()
			if tag != 0 || wt != 0 || next.Offset() != v.start {
				t.Fatalf("% x (%s): got (%d, %d, @%d), want decline at @%d", key, v.name, tag, wt, next.Offset(), v.start)
			}
		}
	}

	allWT := func(yield func(csproto.WireType) bool) {
		for wt := range csproto.WireType(8) {
			if !yield(wt) {
				return
			}
		}
	}

	t.Run("every field 1-2047 with every wire type", func(t *testing.T) {
		for tag := 1; tag <= 2047; tag++ {
			wantLen := 2
			if tag <= 15 {
				wantLen = 1
			}
			for wt := range allWT {
				key := encTag(tag, wt)
				require.Len(t, key, wantLen, "tag=%d wt=%d", tag, wt)
				accept(t, key, tag, wt)
			}
		}
	})

	t.Run("1-byte/2-byte boundary", func(t *testing.T) {
		for wt := range allWT {
			accept(t, []byte{15<<3 | byte(wt)}, 15, wt)
			accept(t, []byte{0x80 | byte(wt), 0x01}, 16, wt)
		}
	})

	t.Run("upper edge: field 2047 accepted, 2048 declined", func(t *testing.T) {
		for wt := range allWT {
			accept(t, []byte{0xf8 | byte(wt), 0x7f}, 2047, wt)
			decline(t, encTag(2048, wt)) // 3-byte key
		}
	})

	t.Run("lower edge: field 0 declined", func(t *testing.T) {
		for wt := range allWT {
			decline(t, []byte{byte(wt)})              // canonical 1-byte key
			decline(t, []byte{0x80 | byte(wt), 0x00}) // zero-padded 2-byte key
		}
	})

	t.Run("zero-padded 2-byte forms of fields 1-15 accepted", func(t *testing.T) {
		for tag := 1; tag <= 15; tag++ {
			for wt := range allWT {
				k := byte(tag<<3) | byte(wt)
				accept(t, []byte{0x80 | k, 0x00}, tag, wt)
			}
		}
	})

	t.Run("keys longer than 2 bytes declined", func(t *testing.T) {
		for _, tag := range []int{2048, 2049, 1 << 14, 1<<18 - 1, 1 << 18, csproto.MaxTagValue} {
			for wt := range allWT {
				decline(t, encTag(tag, wt))
			}
		}
		decline(t, []byte{0x88, 0x80, 0x00}) // zero-padded field 1, 3 bytes
	})

	t.Run("truncated 2-byte keys declined", func(t *testing.T) {
		for tag := 16; tag <= 2047; tag++ {
			for wt := range allWT {
				key := encTag(tag, wt)
				decline(t, key[:1])
			}
		}
	})
}

func TestNextShortTagFromMidBuffer(t *testing.T) {
	t.Parallel()

	// field 1 varint 0, then field 300 (2-byte key 0xe2 0x12), length-delimited
	data := concat(encTag(1, csproto.WireTypeVarint), []byte{0x00}, encTag(300, csproto.WireTypeLengthDelimited))
	c := newCursor(t, data)
	c, tag, wt := c.NextShortTag()
	require.Equal(t, 1, tag)
	require.Equal(t, csproto.WireTypeVarint, wt)
	off, sz, err := c.PeekVarint()
	require.NoError(t, err)
	c = c.Seek(off + sz)

	c, tag, wt = c.NextShortTag()
	assert.Equal(t, 300, tag)
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt)
	assert.False(t, c.More())
}

// ---------- NextTag ----------

func TestNextTag(t *testing.T) {
	t.Parallel()

	t.Run("single-byte tag", func(t *testing.T) {
		data := encTag(1, csproto.WireTypeVarint)
		dec := newCursor(t, data)
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 1, tag)
		assert.Equal(t, csproto.WireTypeVarint, wt)
		assert.Equal(t, len(data), dec.Offset())
	})

	t.Run("all wire types", func(t *testing.T) {
		for _, wt := range []csproto.WireType{
			csproto.WireTypeVarint,
			csproto.WireTypeFixed64,
			csproto.WireTypeLengthDelimited,
			csproto.WireTypeFixed32,
		} {
			data := encTag(5, wt)
			dec := newCursor(t, data)
			dec, tag, gotWT, err := dec.NextTag()
			require.NoError(t, err, "wire type %v", wt)
			assert.Equal(t, 5, tag)
			assert.Equal(t, wt, gotWT)
			assert.False(t, dec.More())
		}
	})

	t.Run("multi-byte tag", func(t *testing.T) {
		data := encTag(16, csproto.WireTypeVarint)
		dec := newCursor(t, data)
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 16, tag)
		assert.Equal(t, csproto.WireTypeVarint, wt)
		assert.False(t, dec.More())
	})

	t.Run("large tag", func(t *testing.T) {
		data := encTag(100000, csproto.WireTypeFixed64)
		dec := newCursor(t, data)
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 100000, tag)
		assert.Equal(t, csproto.WireTypeFixed64, wt)
		assert.False(t, dec.More())
	})

	t.Run("max tag value", func(t *testing.T) {
		data := encTag(csproto.MaxTagValue, csproto.WireTypeLengthDelimited)
		dec := newCursor(t, data)
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, csproto.MaxTagValue, tag)
		assert.Equal(t, csproto.WireTypeLengthDelimited, wt)
	})

	t.Run("sequential tags in one buffer", func(t *testing.T) {
		data := concat(
			encTag(1, csproto.WireTypeVarint), []byte{0x00},
			encTag(2, csproto.WireTypeVarint), []byte{0x01},
		)
		dec := newCursor(t, data)

		dec, tag1, wt1, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 1, tag1)
		assert.Equal(t, csproto.WireTypeVarint, wt1)

		off, sz, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)

		dec, tag2, wt2, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 2, tag2)
		assert.Equal(t, csproto.WireTypeVarint, wt2)
	})

	t.Run("empty buffer", func(t *testing.T) {
		dec := newCursor(t, nil)
		dec, _, _, err := dec.NextTag()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("zero-length buffer", func(t *testing.T) {
		dec := newCursor(t, []byte{})
		dec, _, _, err := dec.NextTag()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("truncated multi-byte varint", func(t *testing.T) {
		dec := newCursor(t, []byte{0x80})
		dec, _, _, err := dec.NextTag()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("all continuation bytes — no terminator", func(t *testing.T) {
		// 10 bytes all with high bit set — exceeds maxVarint, never terminates.
		// Refined to ErrValueOverflow, matching csproto.DecodeVarint.
		data := make([]byte, 10)
		for i := range data {
			data[i] = 0x80
		}
		dec := newCursor(t, data)
		dec, _, _, err := dec.NextTag()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, csproto.ErrValueOverflow)
	})

	t.Run("agrees with csproto.Decoder.DecodeTag for valid tags", func(t *testing.T) {
		for _, tag := range []int{1, 15, 16, 127, 128, 2047, 2048, 100000} {
			for _, wt := range []csproto.WireType{
				csproto.WireTypeVarint,
				csproto.WireTypeFixed64,
				csproto.WireTypeLengthDelimited,
				csproto.WireTypeFixed32,
			} {
				data := encTag(tag, wt)

				dec1 := csproto.NewDecoder(data)
				tag1, wt1, err1 := dec1.DecodeTag()

				dec2 := newCursor(t, data)
				dec2, tag2, wt2, err2 := dec2.NextTag()

				assert.Equal(t, err1, err2, "tag=%d wt=%v", tag, wt)
				assert.Equal(t, tag1, tag2, "tag=%d wt=%v", tag, wt)
				assert.Equal(t, wt1, wt2, "tag=%d wt=%v", tag, wt)
				assert.Equal(t, dec1.Offset(), dec2.Offset(), "tag=%d wt=%v offset", tag, wt)
			}
		}
	})

	t.Run("MaxTagValue accepted, matching csproto.Decoder", func(t *testing.T) {
		for _, wt := range []csproto.WireType{
			csproto.WireTypeVarint,
			csproto.WireTypeFixed64,
			csproto.WireTypeLengthDelimited,
			csproto.WireTypeFixed32,
		} {
			data := encTag(csproto.MaxTagValue, wt)

			dec1 := csproto.NewDecoder(data)
			tag1, wt1, err1 := dec1.DecodeTag()
			require.NoError(t, err1, "csproto.Decoder.DecodeTag should accept MaxTagValue with wt=%v", wt)

			dec2 := newCursor(t, data)
			dec2, tag2, wt2, err2 := dec2.NextTag()
			require.NoError(t, err2, "Cursor.NextTag should accept MaxTagValue with wt=%v", wt)
			assert.Equal(t, csproto.MaxTagValue, tag2)
			assert.Equal(t, wt, wt2)
			assert.Equal(t, tag1, tag2)
			assert.Equal(t, wt1, wt2)
			assert.Equal(t, dec1.Offset(), dec2.Offset())
		}
	})

	t.Run("tag zero rejected for every wire type", func(t *testing.T) {
		for key := byte(0); key < 8; key++ { // tag 0, wire types 0-7
			dec := newCursor(t, []byte{key, 0x00})
			dec, _, _, err := dec.NextTag()
			assert.ErrorIs(t, dec.RefineErr(err), csproto.ErrInvalidFieldTag, "key=%d", key)
			assert.Equal(t, 0, dec.Offset(), "key=%d: offset must be unchanged on error", key)
		}
	})

	// padKey returns the 1-byte key k zero-padded to n bytes:
	// k|0x80, 0x80 × (n-2), 0x00. A trailing 0x01 is appended so the buffer
	// never ends at the key (i.e. errors cannot be mistaken for truncation).
	padKey := func(k byte, n int) []byte {
		out := []byte{k | 0x80}
		for len(out) < n-1 {
			out = append(out, 0x80)
		}
		return append(out, 0x00, 0x01)
	}

	t.Run("zero-padded tag 0 rejected for every wire type and length", func(t *testing.T) {
		// capShifts keeps v exact (0-7) for all-padding bytes, and the v-8
		// unsigned wrap must still reject it.
		for key := byte(0); key < 8; key++ { // tag 0, wire types 0-7
			for n := 2; n <= 10; n++ {
				data := padKey(key, n)
				dec := newCursor(t, data)
				dec, tag, wt, err := dec.NextTag()
				require.Error(t, err, "key=%d n=%d: got tag=%d wt=%v", key, n, tag, wt)
				got := dec.RefineErr(err)
				assert.ErrorIs(t, got, csproto.ErrInvalidFieldTag, "key=%d n=%d", key, n)
				assert.Equal(t, 0, dec.Offset(), "key=%d n=%d: offset must be unchanged on error", key, n)

				_, _, oldErr := csproto.NewDecoder(data).DecodeTag()
				sameSentinel(t, oldErr, got, "key=%d n=%d", key, n)
			}
		}
	})

	t.Run("zero-padded tag 1 accepted for every wire type and length", func(t *testing.T) {
		for wtv := byte(0); wtv < 8; wtv++ {
			key := 1<<3 | wtv
			for n := 2; n <= 10; n++ {
				data := padKey(key, n)

				oldTag, oldWT, oldErr := csproto.NewDecoder(data).DecodeTag()
				require.NoError(t, oldErr, "wt=%d n=%d", wtv, n)

				dec := newCursor(t, data)
				dec, tag, wt, err := dec.NextTag()
				require.NoError(t, err, "wt=%d n=%d", wtv, n)
				assert.Equal(t, 1, tag, "wt=%d n=%d", wtv, n)
				assert.Equal(t, csproto.WireType(wtv), wt, "wt=%d n=%d", wtv, n)
				assert.Equal(t, oldTag, tag, "wt=%d n=%d", wtv, n)
				assert.Equal(t, oldWT, wt, "wt=%d n=%d", wtv, n)
				assert.Equal(t, n, dec.Offset(), "wt=%d n=%d", wtv, n)
			}
		}
	})

	t.Run("MaxTagValue+1 rejected, matching csproto.Decoder", func(t *testing.T) {
		for _, wt := range []csproto.WireType{csproto.WireTypeVarint, csproto.WireTypeLengthDelimited} {
			data := encTag(csproto.MaxTagValue+1, wt)
			dec := newCursor(t, data)
			dec, _, _, err := dec.NextTag()
			got := dec.RefineErr(err)
			assert.ErrorIs(t, got, csproto.ErrInvalidFieldTag, "wt=%v", wt)

			_, _, oldErr := csproto.NewDecoder(data).DecodeTag()
			sameSentinel(t, oldErr, got, "wt=%v", wt)
		}
	})

	t.Run("zero-padded keys up to 10 bytes match csproto.Decoder", func(t *testing.T) {
		// Key for tag 1 / tag MaxTagValue, padded with 0x80 continuation bytes
		// to total length n, terminated by 0x00.
		pad := func(key []byte, n int) []byte {
			out := append([]byte(nil), key...)
			out[len(out)-1] |= 0x80
			for len(out) < n-1 {
				out = append(out, 0x80)
			}
			return append(out, 0x00)
		}
		for _, tc := range []struct {
			tag int
			wt  csproto.WireType
		}{
			{1, csproto.WireTypeVarint},
			{1, csproto.WireTypeLengthDelimited},
			{2047, csproto.WireTypeFixed32},
			{csproto.MaxTagValue, csproto.WireTypeFixed64},
		} {
			key := encTag(tc.tag, tc.wt)
			for n := len(key) + 1; n <= 10; n++ {
				data := pad(key, n)

				oldTag, oldWT, oldErr := csproto.NewDecoder(data).DecodeTag()
				require.NoError(t, oldErr, "tag=%d n=%d", tc.tag, n)

				dec := newCursor(t, data)
				dec, tag, wt, err := dec.NextTag()
				require.NoError(t, err, "tag=%d n=%d", tc.tag, n)
				assert.Equal(t, oldTag, tag, "tag=%d n=%d", tc.tag, n)
				assert.Equal(t, oldWT, wt, "tag=%d n=%d", tc.tag, n)
				assert.Equal(t, n, dec.Offset(), "tag=%d n=%d", tc.tag, n)
			}
		}
	})

	t.Run("non-zero data past byte 5 is rejected, not truncated", func(t *testing.T) {
		// tag 1 key with a stray data bit in byte 6: the true value is >= 2^35,
		// so it must be rejected even though capShifts caps the shift.
		data := []byte{0x88, 0x80, 0x80, 0x80, 0x80, 0x81, 0x00}
		_, _, oldErr := csproto.NewDecoder(data).DecodeTag()
		dec := newCursor(t, data)
		dec, _, _, err := dec.NextTag()
		got := dec.RefineErr(err)
		assert.ErrorIs(t, got, csproto.ErrInvalidFieldTag)
		sameSentinel(t, oldErr, got)
	})

	t.Run("varint overflow — 10 continuation bytes", func(t *testing.T) {
		// 10 bytes all with continuation bit set, followed by a terminator.
		// The varint is valid base-128 but exceeds the maxVarint limit.
		data := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}
		dec := newCursor(t, data)
		dec, _, _, err := dec.NextTag()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, csproto.ErrValueOverflow)
	})

	t.Run("non-canonical — tag 1 varint with leading zeros (2 bytes)", func(t *testing.T) {
		// Canonical encoding of tag=1, varint: 0x08 (1 byte)
		// Non-canonical: 0x88 0x00 — same value, padded with a continuation byte
		// (1<<3)|0 = 8; encoded as 0x88 (8 | 0x80), 0x00 (terminator, value 0)
		data := []byte{0x88, 0x00}
		dec := newCursor(t, data)
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 1, tag)
		assert.Equal(t, csproto.WireTypeVarint, wt)
		assert.Equal(t, 2, dec.Offset())
	})

	t.Run("non-canonical — tag 1 varint with 3 bytes of leading zeros", func(t *testing.T) {
		// tag=1, varint wire type: canonical is 0x08
		// Non-canonical 3-byte: 0x88, 0x80, 0x00
		data := []byte{0x88, 0x80, 0x00}
		dec := newCursor(t, data)
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 1, tag)
		assert.Equal(t, csproto.WireTypeVarint, wt)
		assert.Equal(t, 3, dec.Offset())
	})

	t.Run("non-canonical — tag 2 fixed32 with max padding (5 bytes)", func(t *testing.T) {
		// tag=2, fixed32: canonical key = (2<<3)|5 = 21 = 0x15 (1 byte)
		// Non-canonical 5-byte: 0x95, 0x80, 0x80, 0x80, 0x00
		data := []byte{0x95, 0x80, 0x80, 0x80, 0x00}
		dec := newCursor(t, data)
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		assert.Equal(t, 2, tag)
		assert.Equal(t, csproto.WireTypeFixed32, wt)
		assert.Equal(t, 5, dec.Offset())
	})

	t.Run("non-canonical — agrees with csproto.Decoder.DecodeTag", func(t *testing.T) {
		// Verify non-canonical encodings produce the same result from both decoders
		nonCanonical := [][]byte{
			{0x88, 0x00},             // tag=1, varint, 2 bytes
			{0x88, 0x80, 0x00},       // tag=1, varint, 3 bytes
			{0x95, 0x80, 0x80, 0x00}, // tag=2, fixed32, 4 bytes
		}
		for _, data := range nonCanonical {
			dec1 := csproto.NewDecoder(data)
			tag1, wt1, err1 := dec1.DecodeTag()

			dec2 := newCursor(t, data)
			dec2, tag2, wt2, err2 := dec2.NextTag()

			assert.Equal(t, err1, err2, "data=%x", data)
			assert.Equal(t, tag1, tag2, "data=%x", data)
			assert.Equal(t, wt1, wt2, "data=%x", data)
			assert.Equal(t, dec1.Offset(), dec2.Offset(), "data=%x offset", data)
		}
	})
}

// FuzzNextTag checks Cursor.NextTag (plus RefineErr) against
// csproto.Decoder.DecodeTag, which it is documented to match. Tags are decoded
// repeatedly until the first error so that non-zero starting offsets are
// covered too.
func FuzzNextTag(f *testing.F) {
	for _, wt := range []csproto.WireType{
		csproto.WireTypeVarint,
		csproto.WireTypeFixed64,
		csproto.WireTypeLengthDelimited,
		csproto.WireTypeFixed32,
		3, 4, // group wire types
		6, 7, // invalid wire types are not rejected by either decoder
	} {
		f.Add(encTag(1, wt))
		f.Add(encTag(16, wt))
		f.Add(encTag(csproto.MaxTagValue, wt))
	}
	for _, seed := range [][]byte{
		{},
		{0x00}, // tag 0
		{0x07}, // tag 0, wire type 7
		{0x80}, // truncated
		encVarint(uint64(csproto.MaxTagValue+1) << 3), // tag > MaxTagValue
		encVarint(1 << 32), // key >= 2^32
		{0x88, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00},       // zero-padded tag 1 (10 bytes)
		{0x88, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02},       // 10th byte overflows uint64
		{0x88, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, // 11 bytes
		repeatByte(0xff, 10), // no terminator within window
		concat(encTag(1, csproto.WireTypeVarint), encTag(2, csproto.WireTypeFixed32), []byte{0x80}),
		concat(encTag(3, csproto.WireTypeLengthDelimited), []byte{0x00}),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cur := newCursor(t, data)
		dec := csproto.NewDecoder(data)

		// Every successful decode advances by at least one byte, so this
		// terminates after at most len(data)+1 iterations.
		for {
			start := cur.Offset()
			require.Equal(t, dec.Offset(), start, "data=%x: offsets diverged", data)

			wantTag, wantWT, wantErr := dec.DecodeTag()
			var (
				gotTag int
				gotWT  csproto.WireType
				rawErr error
			)
			cur, gotTag, gotWT, rawErr = cur.NextTag()

			if rawErr != nil {
				require.Equal(t, start, cur.Offset(), "data=%x: offset moved on error", data)

				gotErr := cur.RefineErr(rawErr)
				require.Error(t, gotErr, "data=%x: RefineErr returned nil", data)
				require.Equal(t, start, cur.Offset(), "data=%x: RefineErr moved offset", data)
				require.Error(t, wantErr, "data=%x offset=%d: cursor failed (%v) but Decoder returned tag=%d wt=%d",
					data, start, gotErr, wantTag, wantWT)

				isPublic := false
				for _, s := range publicErrs {
					isPublic = isPublic || errors.Is(gotErr, s)
				}
				require.True(t, isPublic, "data=%x: RefineErr returned non-public error %v", data, gotErr)
				sameSentinel(t, wantErr, gotErr, "data=%x offset=%d", data, start)
				return
			}

			require.NoError(t, wantErr, "data=%x offset=%d: Decoder failed but cursor returned tag=%d wt=%d",
				data, start, gotTag, gotWT)
			require.Equal(t, wantTag, gotTag, "data=%x offset=%d: tag", data, start)
			require.Equal(t, wantWT, gotWT, "data=%x offset=%d: wire type", data, start)
			require.GreaterOrEqual(t, gotTag, 1, "data=%x offset=%d", data, start)
			require.LessOrEqual(t, gotTag, csproto.MaxTagValue, "data=%x offset=%d", data, start)
			require.GreaterOrEqual(t, int(gotWT), 0, "data=%x offset=%d", data, start)
			require.LessOrEqual(t, int(gotWT), 7, "data=%x offset=%d", data, start)
			require.Greater(t, cur.Offset(), start, "data=%x: offset did not advance", data)
			require.LessOrEqual(t, cur.Offset()-start, 10, "data=%x: consumed more than 10 bytes", data)
			require.LessOrEqual(t, cur.Offset(), len(data), "data=%x: offset past end", data)
		}
	})
}

// ---------- PeekVarint ----------

func TestPeekVarint(t *testing.T) {
	t.Parallel()

	t.Run("single byte", func(t *testing.T) {
		data := []byte{0x05}
		dec := newCursor(t, data)
		off, sz, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, off)
		assert.Equal(t, 1, sz)
		assert.False(t, dec.More())
	})

	t.Run("multi byte", func(t *testing.T) {
		data := encVarint(300)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, off)
		assert.Equal(t, len(data), sz)
		assert.False(t, dec.More())
	})

	t.Run("max 10-byte varint", func(t *testing.T) {
		data := encVarint(^uint64(0))
		require.Len(t, data, 10)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, off)
		assert.Equal(t, 10, sz)
	})

	t.Run("at offset", func(t *testing.T) {
		tag := encTag(1, csproto.WireTypeVarint)
		val := encVarint(42)
		data := concat(tag, val)
		dec := newCursor(t, data)
		dec, _, _, err := dec.NextTag()
		require.NoError(t, err)

		off, sz, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, len(tag), off)
		assert.Equal(t, len(val), sz)
		assert.False(t, dec.More())
	})

	t.Run("sequential skips advance offset", func(t *testing.T) {
		data := concat([]byte{0x05}, encVarint(300))
		dec := newCursor(t, data)

		off1, sz1, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off1 + sz1)
		assert.Equal(t, 0, off1)
		assert.Equal(t, 1, sz1)

		off2, sz2, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off2 + sz2)
		assert.Equal(t, 1, off2)
		assert.Equal(t, 2, sz2)
		assert.False(t, dec.More())
	})

	t.Run("empty buffer", func(t *testing.T) {
		dec := newCursor(t, []byte{})
		_, _, err := dec.PeekVarint()
		assert.ErrorIs(t, dec.RefineErr(err), io.ErrUnexpectedEOF)
	})

	t.Run("no terminator/short buffer", func(t *testing.T) {
		data := []byte{0x80, 0x80, 0x80, 0x80, 0x80}
		dec := newCursor(t, data)
		_, _, err := dec.PeekVarint()
		assert.ErrorIs(t, dec.RefineErr(err), io.ErrUnexpectedEOF)
	})

	t.Run("overflow beyond 10 bytes", func(t *testing.T) {
		// 11 continuation bytes followed by a terminator — valid per base-128
		// encoding but exceeds the 10-byte varint limit.
		data := make([]byte, 12)
		for i := 0; i < 11; i++ {
			data[i] = 0x80
		}
		data[11] = 0x00
		dec := newCursor(t, data)
		_, _, err := dec.PeekVarint()
		assert.ErrorIs(t, dec.RefineErr(err), csproto.ErrValueOverflow)
	})

	t.Run("10th byte excess bits overflow", func(t *testing.T) {
		// A valid 10-byte varint where the 10th byte has excess bits.
		// Byte 10 is at shift 63 — only bit 0 is valid (sets bit 63 of uint64).
		// Value 0x02 sets bit 1 which at shift 63 would be bit 64 — overflow.
		data := make([]byte, 10)
		for i := 0; i < 9; i++ {
			data[i] = 0x80 // 9 continuation bytes
		}
		data[9] = 0x02 // terminator with excess bit 1 set
		dec := newCursor(t, data)
		_, _, err := dec.PeekVarint()
		assert.ErrorIs(t, err, csproto.ErrValueOverflow)
	})

	t.Run("10th byte value 0x01 is valid (sets bit 63)", func(t *testing.T) {
		// Byte 10 = 0x01 sets exactly bit 63 of the uint64, which is valid.
		data := make([]byte, 10)
		for i := 0; i < 9; i++ {
			data[i] = 0x80
		}
		data[9] = 0x01 // only bit 0 — valid
		dec := newCursor(t, data)
		off, sz, err := dec.PeekVarint()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, off)
		assert.Equal(t, 10, sz)
	})

	t.Run("10th byte value 0x7F overflows", func(t *testing.T) {
		// All 7 data bits set on the 10th byte — only bit 0 is valid, rest overflow.
		data := make([]byte, 10)
		for i := 0; i < 9; i++ {
			data[i] = 0x80
		}
		data[9] = 0x7F
		dec := newCursor(t, data)
		_, _, err := dec.PeekVarint()
		assert.ErrorIs(t, err, csproto.ErrValueOverflow)
	})
}

// ---------- PeekFixed32 / PeekFixed64 ----------

func TestPeekFixed(t *testing.T) {
	t.Parallel()

	t.Run("fixed32", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04}
		dec := newCursor(t, data)
		off, sz, err := dec.PeekFixed32()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, off)
		assert.Equal(t, 4, sz)
		assert.False(t, dec.More())
	})

	t.Run("fixed64", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		dec := newCursor(t, data)
		off, sz, err := dec.PeekFixed64()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, off)
		assert.Equal(t, 8, sz)
		assert.False(t, dec.More())
	})

	t.Run("fixed32/extra data after", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF}
		dec := newCursor(t, data)
		off, sz, err := dec.PeekFixed32()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, off)
		assert.Equal(t, 4, sz)
		assert.True(t, dec.More())
		assert.Equal(t, 4, dec.Offset())
	})

	t.Run("fixed32/truncated", func(t *testing.T) {
		dec := newCursor(t, []byte{0x01, 0x02, 0x03})
		_, _, err := dec.PeekFixed32()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("fixed32/empty", func(t *testing.T) {
		dec := newCursor(t, []byte{})
		_, _, err := dec.PeekFixed32()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("fixed64/truncated", func(t *testing.T) {
		dec := newCursor(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})
		_, _, err := dec.PeekFixed64()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("fixed64/empty", func(t *testing.T) {
		dec := newCursor(t, []byte{})
		_, _, err := dec.PeekFixed64()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

// ---------- PeekBytes ----------

func TestPeekBytes(t *testing.T) {
	t.Parallel()

	t.Run("requires 64-bit platform", func(t *testing.T) {
		if unsafe.Sizeof(uintptr(0)) < 8 {
			t.Fatal("PeekBytes uses int for length, which must be 64-bit to hold varint-decoded sizes")
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		data := encVarint(0)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, len(data), off)
		assert.Equal(t, 0, sz)
		assert.False(t, dec.More())
	})

	t.Run("small payload", func(t *testing.T) {
		payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		data := concat(encVarint(uint64(len(payload))), payload)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, len(encVarint(4)), off)
		assert.Equal(t, 4, sz)
		assert.False(t, dec.More())
	})

	t.Run("payload content accessible via offset+length", func(t *testing.T) {
		payload := []byte("hello")
		data := concat(encVarint(uint64(len(payload))), payload)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, payload, data[off:off+sz])
	})

	t.Run("large length varint", func(t *testing.T) {
		payload := make([]byte, 200)
		for i := range payload {
			payload[i] = byte(i)
		}
		data := concat(encVarint(200), payload)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 200, sz)
		assert.Equal(t, payload, data[off:off+sz])
		assert.False(t, dec.More())
	})

	t.Run("at offset after tag", func(t *testing.T) {
		tag := encTag(3, csproto.WireTypeLengthDelimited)
		payload := []byte{0x01, 0x02, 0x03}
		data := concat(tag, encVarint(3), payload)
		dec := newCursor(t, data)
		dec, _, _, err := dec.NextTag()
		require.NoError(t, err)

		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 3, sz)
		assert.Equal(t, payload, data[off:off+sz])
		assert.False(t, dec.More())
	})

	t.Run("sequential skips", func(t *testing.T) {
		p1 := []byte{0xAA, 0xBB}
		p2 := []byte{0xCC, 0xDD, 0xEE}
		data := concat(encVarint(2), p1, encVarint(3), p2)
		dec := newCursor(t, data)

		off1, sz1, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off1 + sz1)
		assert.Equal(t, 2, sz1)
		assert.Equal(t, p1, data[off1:off1+sz1])

		off2, sz2, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off2 + sz2)
		assert.Equal(t, 3, sz2)
		assert.Equal(t, p2, data[off2:off2+sz2])
		assert.False(t, dec.More())
	})

	t.Run("extra data after payload", func(t *testing.T) {
		payload := []byte{0x01, 0x02}
		trailer := []byte{0xFF, 0xFF, 0xFF}
		data := concat(encVarint(2), payload, trailer)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 2, sz)
		assert.Equal(t, payload, data[off:off+sz])
		assert.True(t, dec.More())
	})

	t.Run("empty buffer", func(t *testing.T) {
		dec := newCursor(t, []byte{})
		_, _, err := dec.PeekBytes()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("length varint truncated", func(t *testing.T) {
		dec := newCursor(t, []byte{0x80})
		_, _, err := dec.PeekBytes()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("payload shorter than declared length", func(t *testing.T) {
		data := concat(encVarint(10), []byte{0x01, 0x02, 0x03})
		dec := newCursor(t, data)
		_, _, err := dec.PeekBytes()
		assert.ErrorIs(t, dec.RefineErr(err), io.ErrUnexpectedEOF)
	})

	t.Run("payload exactly one byte short", func(t *testing.T) {
		data := concat(encVarint(5), []byte{0x01, 0x02, 0x03, 0x04})
		dec := newCursor(t, data)
		_, _, err := dec.PeekBytes()
		assert.ErrorIs(t, dec.RefineErr(err), io.ErrUnexpectedEOF)
	})

	t.Run("huge declared length", func(t *testing.T) {
		data := concat(encVarint(1<<32), []byte{0x01})
		dec := newCursor(t, data)
		_, _, err := dec.PeekBytes()
		assert.ErrorIs(t, dec.RefineErr(err), csproto.ErrLenOverflow)
	})

	t.Run("length varint all continuation bytes", func(t *testing.T) {
		data := make([]byte, 10)
		for i := range data {
			data[i] = 0x80
		}
		dec := newCursor(t, data)
		_, _, err := dec.PeekBytes()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, csproto.ErrValueOverflow)
	})

	t.Run("zero-padded 10-byte length prefix (value 0) is accepted", func(t *testing.T) {
		// 9 continuation bytes followed by a terminator and payload: a valid
		// zero-padded 10-byte length prefix for length 0.
		data := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x01, 0x02}
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 10, off)
		assert.Equal(t, 0, sz)
		assert.Equal(t, 10, dec.Offset())
	})

	t.Run("zero-padded length prefixes of every width match csproto.Decoder.DecodeBytes", func(t *testing.T) {
		payload := []byte("hello, world")
		for _, length := range []int{0, 1, 3, 127, 128, len(payload)} {
			canon := encVarint(uint64(length))
			for n := len(canon); n <= 10; n++ {
				// Pad the canonical prefix to n bytes: set continuation on the
				// last canonical byte, add 0x80s, terminate with 0x00.
				prefix := append([]byte(nil), canon...)
				if n > len(canon) {
					prefix[len(prefix)-1] |= 0x80
					for len(prefix) < n-1 {
						prefix = append(prefix, 0x80)
					}
					prefix = append(prefix, 0x00)
				}
				body := payload
				if length > len(body) {
					body = repeatByte('x', length)
				}
				data := concat(prefix, body[:length], []byte{0xff}) // trailing byte must not be consumed

				want, oldErr := csproto.NewDecoder(data).DecodeBytes()
				require.NoError(t, oldErr, "len=%d n=%d", length, n)

				dec := newCursor(t, data)
				off, sz, err := dec.PeekBytes()
				require.NoError(t, err, "len=%d n=%d", length, n)
				dec = dec.Seek(off + sz)
				assert.Equal(t, n, off, "len=%d n=%d", length, n)
				assert.Equal(t, length, sz, "len=%d n=%d", length, n)
				assert.Equal(t, want, data[off:off+sz], "len=%d n=%d", length, n)
				assert.Equal(t, n+length, dec.Offset(), "len=%d n=%d", length, n)
			}
		}
	})

	t.Run("non-zero data past byte 5 of the length is rejected, not truncated", func(t *testing.T) {
		// Length 3 with a stray data bit in byte 6: the true length is >= 2^35,
		// so it must be rejected even though capShifts caps the shift and the
		// buffer has plenty of bytes after the prefix.
		data := concat([]byte{0x83, 0x80, 0x80, 0x80, 0x80, 0x81, 0x00}, repeatByte('x', 64))
		_, oldErr := csproto.NewDecoder(data).DecodeBytes()
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.Error(t, err)
		assert.Equal(t, 0, off)
		assert.Equal(t, 0, sz)
		assert.Equal(t, 0, dec.Offset())
		got := dec.RefineErr(err)
		assert.ErrorIs(t, got, csproto.ErrLenOverflow)
		sameSentinel(t, oldErr, got)
	})

	t.Run("length varint large value does not overflow bounds check", func(t *testing.T) {
		// Craft a 5-byte varint that decodes to a large value (all 35 data bits set = 34,359,738,367).
		// With the subtraction-form bounds check, this correctly returns ErrUnexpectedEOF
		// instead of allowing offset+length to overflow on architectures where int is small.
		data := make([]byte, 20) // buffer smaller than declared length
		for i := 0; i < 4; i++ {
			data[i] = 0xFF // continuation + 7 data bits set
		}
		data[4] = 0x7F // terminator + 7 data bits set → 35 bits total ≈ 34 GiB
		dec := newCursor(t, data)
		_, _, err := dec.PeekBytes()
		assert.ErrorIs(t, dec.RefineErr(err), csproto.ErrLenOverflow, "should reject oversized length, not panic")
	})

	t.Run("length varint MaxInt64 does not overflow bounds check", func(t *testing.T) {
		// Craft a 9-byte varint that decodes to MaxInt64 (all 63 data bits set).
		// Without the subtraction-form bounds check (length <= len(d.p)-offset),
		// the old form (offset+length <= len(d.p)) wraps negative on signed int64
		// overflow, passes the check, and sets d.offset negative → panic.
		data := make([]byte, 20)
		for i := 0; i < 8; i++ {
			data[i] = 0xFF // continuation + 7 data bits set
		}
		data[8] = 0x7F // terminator + 7 data bits set → 63 bits = MaxInt64
		dec := newCursor(t, data)
		_, _, err := dec.PeekBytes()
		assert.ErrorIs(t, dec.RefineErr(err), csproto.ErrLenOverflow, "should reject, not panic from integer overflow")
	})

	t.Run("regression: offset+length signed overflow", func(t *testing.T) {
		// This test reproduces the exact exploit that crashed the old code.
		//
		// The old bounds check was:
		//   if offset+length <= len(d.p) { ... }
		//
		// With a 9-byte varint encoding MaxInt64 as the length prefix:
		//   length = math.MaxInt64  (9223372036854775807)
		//   offset = 10             (9 varint bytes + 1 for d.offset=0 start)
		//   offset + length = 10 + 9223372036854775807 = -9223372036854775799  (signed overflow!)
		//   -9223372036854775799 <= 1024  → TRUE  → entered success path
		//   d.offset = -9223372036854775799  → next d.p[d.offset:] → PANIC
		//
		// The fix uses subtraction (length <= len(d.p)-offset) which never overflows.
		//
		// Verify: no panic, returns an error, and decoder offset is unchanged.

		buf := make([]byte, 1024)
		// Encode MaxInt64 as a 9-byte varint length prefix at the start of buf.
		for i := 0; i < 8; i++ {
			buf[i] = 0xFF // continuation byte: 7 data bits all set
		}
		buf[8] = 0x7F // terminator: 7 data bits all set → 9×7 = 63 bits → MaxInt64

		dec := newCursor(t, buf)
		startOffset := dec.Offset()

		off, sz, err := dec.PeekBytes()

		// Must not panic (the old code panicked here).
		// Must return an error.
		require.Error(t, err, "MaxInt64 length must be rejected")
		assert.ErrorIs(t, dec.RefineErr(err), csproto.ErrLenOverflow)

		// Return values must be zero on error.
		assert.Equal(t, 0, off, "offset must be zero on error")
		assert.Equal(t, 0, sz, "length must be zero on error")

		// Decoder offset must not have moved.
		assert.Equal(t, startOffset, dec.Offset(), "decoder offset must be unchanged on error")
	})
}

// ---------- Integration: full field round-trip ----------

func TestCursorFieldRoundTrip(t *testing.T) {
	t.Parallel()

	var buf [64]byte
	n := 0
	n += csproto.EncodeTag(buf[n:], 1, csproto.WireTypeVarint)
	n += csproto.EncodeVarint(buf[n:], 150)
	varintEnd := n
	n += csproto.EncodeTag(buf[n:], 2, csproto.WireTypeFixed32)
	buf[n], buf[n+1], buf[n+2], buf[n+3] = 0x04, 0x03, 0x02, 0x01
	n += 4
	n += csproto.EncodeTag(buf[n:], 3, csproto.WireTypeFixed64)
	for i := 0; i < 8; i++ {
		buf[n+i] = byte(i + 1)
	}
	n += 8
	n += csproto.EncodeTag(buf[n:], 4, csproto.WireTypeLengthDelimited)
	n += csproto.EncodeVarint(buf[n:], 2)
	buf[n], buf[n+1] = 'h', 'i'
	n += 2

	data := buf[:n]
	dec := newCursor(t, data)

	dec, tag, wt, err := dec.NextTag()
	require.NoError(t, err)
	assert.Equal(t, 1, tag)
	assert.Equal(t, csproto.WireTypeVarint, wt)
	off, sz, err := dec.PeekVarint()
	require.NoError(t, err)
	dec = dec.Seek(off + sz)
	v, _, err := csproto.DecodeVarint(data[off : off+sz])
	require.NoError(t, err)
	assert.Equal(t, uint64(150), v)
	assert.Equal(t, varintEnd, dec.Offset())

	dec, tag, wt, err = dec.NextTag()
	require.NoError(t, err)
	assert.Equal(t, 2, tag)
	assert.Equal(t, csproto.WireTypeFixed32, wt)
	off, sz, err = dec.PeekFixed32()
	require.NoError(t, err)
	dec = dec.Seek(off + sz)
	assert.Equal(t, 4, sz)
	assert.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, data[off:off+sz])

	dec, tag, wt, err = dec.NextTag()
	require.NoError(t, err)
	assert.Equal(t, 3, tag)
	assert.Equal(t, csproto.WireTypeFixed64, wt)
	off, sz, err = dec.PeekFixed64()
	require.NoError(t, err)
	dec = dec.Seek(off + sz)
	assert.Equal(t, 8, sz)

	dec, tag, wt, err = dec.NextTag()
	require.NoError(t, err)
	assert.Equal(t, 4, tag)
	assert.Equal(t, csproto.WireTypeLengthDelimited, wt)
	off, sz, err = dec.PeekBytes()
	require.NoError(t, err)
	dec = dec.Seek(off + sz)
	assert.Equal(t, 2, sz)
	assert.Equal(t, []byte("hi"), data[off:off+sz])

	assert.False(t, dec.More(), "should have consumed the entire buffer")
}

// ---------- RefineErr ----------

// publicErrs are the sentinel errors callers may test for with errors.Is.
var publicErrs = []error{
	io.ErrUnexpectedEOF,
	csproto.ErrInvalidVarintData,
	csproto.ErrValueOverflow,
	csproto.ErrInvalidFieldTag,
	csproto.ErrLenOverflow,
}

// sameSentinel reports whether a and b match the same set of publicErrs.
func sameSentinel(t *testing.T, a, b error, msgAndArgs ...any) {
	t.Helper()
	for _, s := range publicErrs {
		assert.Equal(t, errors.Is(a, s), errors.Is(b, s),
			append([]any{"errors.Is(%v): csproto=%v cursor=%v", s, a, b}, msgAndArgs...)...)
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestRefineErr(t *testing.T) {
	t.Parallel()

	t.Run("passes through nil and non-sentinel errors", func(t *testing.T) {
		dec := newCursor(t, []byte{0x80})
		assert.NoError(t, dec.RefineErr(nil))
		assert.Same(t, io.ErrUnexpectedEOF, dec.RefineErr(io.ErrUnexpectedEOF))
		other := errors.New("other")
		assert.Same(t, other, dec.RefineErr(other))
	})

	t.Run("NextTag matches csproto.Decoder.DecodeTag on malformed input", func(t *testing.T) {
		inputs := map[string][]byte{
			"empty":                       {},
			"1 continuation byte":         {0x80},
			"8 continuation bytes":        repeatByte(0x80, 8),
			"9 continuation bytes":        repeatByte(0x80, 9), // exactly fills the 64-bit window
			"10 continuation bytes":       repeatByte(0x80, 10),
			"11 continuation bytes":       repeatByte(0x80, 11),
			"10-byte varint, 10th byte=1": append(repeatByte(0x80, 9), 0x01),
			"10-byte varint, 10th byte=2": append(repeatByte(0x80, 9), 0x02), // overflows uint64
		}
		for name, data := range inputs {
			_, _, oldErr := csproto.NewDecoder(data).DecodeTag()
			require.Error(t, oldErr, name)

			dec := newCursor(t, data)
			dec, _, _, err := dec.NextTag()
			require.Error(t, err, name)
			sameSentinel(t, oldErr, dec.RefineErr(err), name)
			assert.Equal(t, 0, dec.Offset(), "%s: offset must be unchanged on error", name)
		}
	})

	// mainSkip mirrors how main's lazyproto decode loop consumed a field
	// value: DecodeTag, then Skip(tag, wt) in fast mode. data must start
	// with a one-byte tag key.
	mainSkip := func(data []byte) error {
		d := csproto.NewDecoder(data)
		d.SetMode(csproto.DecoderModeFast)
		tag, wt, err := d.DecodeTag()
		if err != nil {
			return err
		}
		_, err = d.Skip(tag, wt)
		return err
	}

	t.Run("PeekBytes matches csproto.Decoder DecodeBytes and Skip on malformed length prefixes", func(t *testing.T) {
		inputs := map[string][]byte{
			"empty":                         {},
			"1 continuation byte":           {0x80},
			"8 continuation bytes":          repeatByte(0x80, 8),
			"9 continuation bytes":          repeatByte(0x80, 9),
			"10 continuation bytes":         repeatByte(0x80, 10),
			"11 continuation bytes":         repeatByte(0x80, 11),
			"10-byte varint, 10th byte=2":   append(repeatByte(0x80, 9), 0x02), // overflows uint64
			"10-byte length > 2 GiB":        append(repeatByte(0xff, 9), 0x01), // valid varint, huge length
			"payload shorter than length":   {0x05, 0x01, 0x02},
			"length = 2 GiB - 1, short buf": concat(encVarint(math.MaxInt32), []byte{0x01}),
			"length = 2 GiB, short buf":     concat(encVarint(math.MaxInt32+1), []byte{0x01}),
			"5-byte length = 3 GiB":         concat(encVarint(3<<30), []byte{0x01}),
			"5-byte length = 1<<32":         concat(encVarint(1<<32), []byte{0x01}),
			"9-byte length = MaxInt64":      concat(encVarint(math.MaxInt64), []byte{0x01}),
		}
		for name, data := range inputs {
			// main used DecodeBytes for tracked tags and Skip for untracked ones.
			_, oldErr := csproto.NewDecoder(data).DecodeBytes()
			require.Error(t, oldErr, name)
			oldSkipErr := mainSkip(concat(encTag(1, csproto.WireTypeLengthDelimited), data))
			require.Error(t, oldSkipErr, name)
			sameSentinel(t, oldErr, oldSkipErr, name+" (DecodeBytes vs Skip)")

			dec := newCursor(t, data)
			_, _, err := dec.PeekBytes()
			require.Error(t, err, name)
			sameSentinel(t, oldErr, dec.RefineErr(err), name)
			assert.Equal(t, 0, dec.Offset(), "%s: offset must be unchanged on error", name)
		}
	})

	t.Run("PeekVarint matches csproto.Decoder.Skip on malformed varint values", func(t *testing.T) {
		inputs := map[string][]byte{
			"empty":                       {},
			"1 continuation byte":         {0x80},
			"9 continuation bytes":        repeatByte(0x80, 9),
			"10 continuation bytes":       repeatByte(0x80, 10),
			"11 continuation bytes":       repeatByte(0x80, 11),
			"10-byte varint, 10th byte=2": append(repeatByte(0x80, 9), 0x02), // overflows uint64
		}
		for name, data := range inputs {
			key := encTag(1, csproto.WireTypeVarint)
			oldErr := mainSkip(concat(key, data))
			require.Error(t, oldErr, name)

			dec := newCursor(t, concat(key, data))
			dec, _, _, err := dec.NextTag()
			require.NoError(t, err, name)
			_, _, err = dec.PeekVarint()
			require.Error(t, err, name)
			sameSentinel(t, oldErr, dec.RefineErr(err), name)
			assert.Equal(t, len(key), dec.Offset(), "%s: offset must be unchanged on error", name)
		}
	})

	t.Run("regression: truncated length prefix is io.ErrUnexpectedEOF", func(t *testing.T) {
		// tag 2, length-delimited, unterminated length varint
		dec := newCursor(t, []byte{0x12, 0x80})
		dec, tag, wt, err := dec.NextTag()
		require.NoError(t, err)
		require.Equal(t, 2, tag)
		require.Equal(t, csproto.WireTypeLengthDelimited, wt)
		_, _, err = dec.PeekBytes()
		assert.ErrorIs(t, dec.RefineErr(err), io.ErrUnexpectedEOF)
	})

	t.Run("valid 10-byte tag varint is ErrInvalidFieldTag", func(t *testing.T) {
		data := append(repeatByte(0x80, 9), 0x01)
		dec := newCursor(t, data)
		dec, _, _, err := dec.NextTag()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, csproto.ErrInvalidFieldTag)
		// key = 1<<63, so the field number is 1<<60.
		assert.Contains(t, err.Error(), "invalid tag value (1152921504606846976)")
	})

	t.Run("ErrInvalidFieldTag reports the field number", func(t *testing.T) {
		for key, want := range map[byte]string{
			0x00: "invalid tag value (0)", // field 0, wt=varint
			0x07: "invalid tag value (0)", // field 0, wt=7: field number, not raw key
		} {
			dec := newCursor(t, []byte{key})
			dec, _, _, err := dec.NextTag()
			err = dec.RefineErr(err)
			assert.ErrorIs(t, err, csproto.ErrInvalidFieldTag, "key=%#x", key)
			assert.Contains(t, err.Error(), want, "key=%#x", key)
		}
	})

	t.Run("valid 10-byte length prefix > 2 GiB is ErrLenOverflow", func(t *testing.T) {
		data := append(repeatByte(0xff, 9), 0x01)
		dec := newCursor(t, data)
		_, _, err := dec.PeekBytes()
		err = dec.RefineErr(err)
		assert.ErrorIs(t, err, csproto.ErrLenOverflow)
		assert.Contains(t, err.Error(), "invalid length (18446744073709551615) for length-delimited field")
	})

	t.Run("zero-padded 10-byte length prefix matches csproto.Decoder.DecodeBytes", func(t *testing.T) {
		data := append(repeatByte(0x80, 9), 0x00) // length 0, padded to 10 bytes
		_, oldErr := csproto.NewDecoder(data).DecodeBytes()
		require.NoError(t, oldErr)
		dec := newCursor(t, data)
		off, sz, err := dec.PeekBytes()
		require.NoError(t, err)
		dec = dec.Seek(off + sz)
		assert.Equal(t, 0, sz)
		assert.Equal(t, 10, dec.Offset())
	})
}

// ---------- NewCursor ----------

func TestNewCursor(t *testing.T) {
	t.Run("accepts small and empty buffers", func(t *testing.T) {
		for _, p := range [][]byte{nil, {}, {0x08, 0x01}} {
			c, err := wire.NewCursor(p)
			require.NoError(t, err)
			assert.Equal(t, 0, c.Offset())
			assert.Equal(t, len(p) > 0, c.More())
		}
	})

	t.Run("zero value is an empty cursor", func(t *testing.T) {
		var c wire.Cursor
		assert.False(t, c.More())
		assert.Equal(t, 0, c.Offset())
	})

	t.Run("enforces the 2 GiB limit", func(t *testing.T) {
		if testing.Short() {
			t.Skip("allocates a 2 GiB buffer; skipped with -short")
		}
		if strconv.IntSize < 64 {
			t.Skip("a buffer over math.MaxInt32 bytes cannot exist on 32-bit platforms")
		}
		// Not parallel: keep at most one 2 GiB reservation alive at a time.
		// Fresh pages from the OS are already zero, so this reserves address
		// space without touching (and committing) the memory.
		// int64 so the size is not an int constant (which would not compile on
		// 32-bit, where this test is skipped above).
		size := int64(math.MaxInt32) + 1
		big := make([]byte, size)

		c, err := wire.NewCursor(big[:math.MaxInt32])
		require.NoError(t, err, "exactly math.MaxInt32 bytes must be accepted")
		assert.True(t, c.More())

		c, err = wire.NewCursor(big)
		require.ErrorIs(t, err, wire.ErrBufferTooLarge)
		assert.ErrorIs(t, err, csproto.ErrLenOverflow)
		assert.False(t, c.More(), "rejected cursor must be the zero value")
	})
}
