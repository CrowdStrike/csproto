package lazyproto

import (
	"fmt"
	"math"
	"strconv"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CrowdStrike/csproto"
)

func TestNestedDecodeResultSkipCloseResetOnPool(t *testing.T) {
	// This test directly verifies the invariant: after a parent closes a
	// nested DecodeResult, the object returned to the pool must have
	// skipClose=false. Without the fix, skipClose remains true in the pool
	// which causes the error path in decodeWithPool to leak objects (Close()
	// is a no-op when skipClose=true).

	// message Outer { Inner inner = 1; }
	// message Inner { uint32 id = 1; }
	outerMsg := []byte{
		// field 1: nested message (2 bytes)
		(1 << 3) | 2, 0x02,
		// inner.field 1: varint 42
		(1 << 3), 0x2a,
	}

	def := NewDef()
	_ = def.NestedTag(1, 1)

	dec, err := NewDecoder(def, WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	// Cycle a nested object through the pool:
	// pool.Get → nested use (skipClose=true) → parent.Close → pool.Put
	res, err := dec.Decode(outerMsg)
	require.NoError(t, err)
	require.False(t, res.skipClose, "root result should never had skipClose=true")

	nested, err := res.NestedResult(1)
	require.NoError(t, err)
	require.True(t, nested.skipClose, "nested result should have skipClose=true while owned by parent")

	val, err := nested.UInt32Value(1)
	require.NoError(t, err)
	assert.Equal(t, uint32(42), val)

	// Grab reference to nested decoder's pool before closing.
	nestedDec := res.nestedDecoders[0]

	require.NoError(t, res.Close())

	// Pull directly from the nested decoder's pool and verify skipClose was reset.
	pooled, ok := nestedDec.pool.Get().(*DecodeResult)
	require.True(t, ok, "pool should return a *DecodeResult")
	defer nestedDec.pool.Put(pooled)

	// THE KEY ASSERTION: without the fix, this is true (the bug).
	// With the fix, close() resets skipClose=false before pool.Put.
	assert.False(t, pooled.skipClose,
		"object returned to pool must have skipClose=false; if true, the error path in decodeWithPool leaks it via the Close() no-op")
}

func TestNestedDecodeResultPoolLeak_ErrorPath(t *testing.T) {
	// This test demonstrates the pool drain caused by the skipClose bug.
	//
	// Scenario: a nested DecodeResult with skipClose=true is pulled from the
	// pool, then a decode error occurs. The original code called res.Close()
	// (capital C) which is a no-op when skipClose=true, permanently leaking
	// the object. We detect this by instrumenting the pool's New function
	// with a counter: if objects leak, New fires to create replacements.
	//
	// This requires BOTH fixes to pass:
	// 1. close() resets skipClose=false before pool.Put
	// 2. decodeWithPool error path calls close() not Close()

	// Valid outer with nested inner
	validOuter := []byte{
		// field 1: nested message (7 bytes)
		(1 << 3) | 2, 0x07,
		// inner.field 1: string "hello"
		(1 << 3) | 2, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
	}
	// Corrupt outer: nested bytes contain unsupported wire type
	corruptOuter := []byte{
		// field 1: nested message (2 bytes)
		(1 << 3) | 2, 0x02,
		// tag with wire type 6 (invalid)
		(1 << 3) | 6, 0xFF,
	}

	def := NewDef()
	_ = def.NestedTag(1, 1)

	dec, err := NewDecoder(def, WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	// Decode once to get access to the nested decoder's pool via DecodeResult.
	res, err := dec.Decode(validOuter)
	require.NoError(t, err)
	nestedDec := res.nestedDecoders[0]
	_, err = res.NestedResult(1)
	require.NoError(t, err)
	require.NoError(t, res.Close())

	// Instrument the nested decoder's pool with a call counter on New.
	var newCalls atomic.Int64
	origNew := nestedDec.pool.New
	nestedDec.pool.New = func() any {
		newCalls.Add(1)
		return origNew()
	}

	// Reset counter.
	newCalls.Store(0)

	// Run success→error cycles. If the error path leaks pool objects,
	// subsequent Gets will have to call New to create fresh ones.
	const cycles = 10
	for i := 0; i < cycles; i++ {
		// Success: puts nested object back in pool via parent.close()
		res, err := dec.Decode(validOuter)
		require.NoError(t, err)
		_, err = res.NestedResult(1)
		require.NoError(t, err)
		require.NoError(t, res.Close())

		// Error: pulls from pool, decode fails, should return to pool
		res, err = dec.Decode(corruptOuter)
		require.NoError(t, err)
		_, _ = res.NestedResult(1) // expected error
		require.NoError(t, res.Close())
	}

	// With the fix: objects are recycled on error → New is never called → 0
	// Without the fix: each error leaks one object → New fires to replace → cycles count
	assert.Equal(t, int64(0), newCalls.Load(),
		"pool.New should not be called during steady-state operation; %d calls indicates objects leaked from the pool on decode errors",
		newCalls.Load())
}

func TestNestedResultEmptyNestedMessage(t *testing.T) {
	// message Outer { Inner inner = 1; }
	// message Inner { uint32 id = 1; }
	//
	// Inner is present on the wire but has a zero-length payload (e.g. Inner{}
	// with no fields set). (*Decoder).decodeWithPool short-circuits on empty
	// data and returns (nil, nil) instead of a *DecodeResult, so NestedResult
	// must not dereference the result before checking for nil.
	outerMsg := []byte{
		// field 1: nested message (0 bytes)
		(1 << 3) | 2, 0x00,
	}

	def := NewDef()
	_ = def.NestedTag(1, 1)

	dec, err := NewDecoder(def, WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	res, err := dec.Decode(outerMsg)
	require.NoError(t, err)

	nested, err := res.NestedResult(1)
	require.NoError(t, err)
	assert.Nil(t, nested)

	require.NoError(t, res.Close())
}

func TestNestedResultsEmptyNestedMessage(t *testing.T) {
	// message Outer { repeated Inner items = 1; }
	// message Inner { uint32 id = 1; }
	//
	// One of the repeated entries is present but has a zero-length payload
	// (e.g. Inner{} with no fields set). NestedResults must not dereference
	// the corresponding nil *DecodeResult.
	outerMsg := []byte{
		// field 1: first nested (2 bytes): id=1
		(1 << 3) | 2, 0x02, (1 << 3), 0x01,
		// field 1: second nested (0 bytes)
		(1 << 3) | 2, 0x00,
	}

	def := NewDef()
	_ = def.NestedTag(1, 1)

	dec, err := NewDecoder(def, WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	res, err := dec.Decode(outerMsg)
	require.NoError(t, err)

	results, err := res.NestedResults(1)
	require.NoError(t, err)
	require.Len(t, results, 2)

	v, err := results[0].UInt32Value(1)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), v)

	assert.Nil(t, results[1])

	require.NoError(t, res.Close())
}

func TestNestedDecodeResultPoolReuse_MultipleNested(t *testing.T) {
	// Verify pool reuse works correctly with repeated nested results (NestedResults plural).
	// After Close(), all nested results should be returned with skipClose=false.

	// message Outer { repeated Inner items = 1; }
	// message Inner { uint32 id = 1; }
	outerMsg := []byte{
		// field 1: first nested (2 bytes): id=1
		(1 << 3) | 2, 0x02, (1 << 3), 0x01,
		// field 1: second nested (2 bytes): id=2
		(1 << 3) | 2, 0x02, (1 << 3), 0x02,
		// field 1: third nested (2 bytes): id=3
		(1 << 3) | 2, 0x02, (1 << 3), 0x03,
	}

	def := NewDef()
	_ = def.NestedTag(1, 1)

	dec, err := NewDecoder(def, WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	// First cycle: primes the pool with 3 nested objects.
	res, err := dec.Decode(outerMsg)
	require.NoError(t, err)
	nestedDec := res.nestedDecoders[0]
	results, err := res.NestedResults(1)
	require.NoError(t, err)
	require.Len(t, results, 3)
	for i, r := range results {
		v, err := r.UInt32Value(1)
		require.NoError(t, err)
		assert.Equal(t, uint32(i+1), v)
		assert.True(t, r.skipClose, "nested result %d should have skipClose=true while owned by parent", i)
	}
	require.NoError(t, res.Close())

	// Verify all pooled objects have skipClose=false.
	pooledObjs := make([]*DecodeResult, 0, 3)
	for i := 0; i < 3; i++ {
		obj, ok := nestedDec.pool.Get().(*DecodeResult)
		if !ok {
			break
		}
		assert.False(t, obj.skipClose,
			"pooled nested result %d should have skipClose=false after parent close", i)
		pooledObjs = append(pooledObjs, obj)
	}
	// Return them
	for _, obj := range pooledObjs {
		nestedDec.pool.Put(obj)
	}

	// Instrument and run steady-state cycles. No New calls expected.
	var newCalls atomic.Int64
	origNew := nestedDec.pool.New
	nestedDec.pool.New = func() any {
		newCalls.Add(1)
		return origNew()
	}

	for cycle := 0; cycle < 20; cycle++ {
		res, err := dec.Decode(outerMsg)
		require.NoError(t, err)
		_, err = res.NestedResults(1)
		require.NoError(t, err)
		require.NoError(t, res.Close())
	}

	assert.Equal(t, int64(0), newCalls.Load(),
		"pool.New should not fire during steady-state NestedResults reuse; got %d calls", newCalls.Load())
}

func TestCloseReleasesFastModeAliases(t *testing.T) {
	// In DecoderModeFast, StringValues/BytesValues cache slices whose
	// elements alias the input buffer (unsafe.String / raw sub-slices).
	// close() must zero them so the pooled DecodeResult does not keep
	// the previous input reachable.

	// field 1: repeated string "ab", "cd"; field 2: repeated bytes "xy", "zw"
	msg := []byte{
		(1 << 3) | 2, 0x02, 'a', 'b',
		(1 << 3) | 2, 0x02, 'c', 'd',
		(2 << 3) | 2, 0x02, 'x', 'y',
		(2 << 3) | 2, 0x02, 'z', 'w',
	}

	def := NewDef(1, 2)
	dec, err := NewDecoder(def, WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	res, err := dec.Decode(msg)
	require.NoError(t, err)

	ss, err := res.StringValues(1)
	require.NoError(t, err)
	assert.Equal(t, []string{"ab", "cd"}, ss)

	bs, err := res.BytesValues(2)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("xy"), []byte("zw")}, bs)

	require.NoError(t, res.Close())

	for i := range res.slab {
		buf := res.slab[i].cold.buffers
		require.NotNil(t, buf, "fast mode should allocate buffers for field slot %d", i)
		assert.Empty(t, buf.stringSlice, "slot %d stringSlice should be reset", i)
		assert.Empty(t, buf.bytesSlice, "slot %d bytesSlice should be reset", i)
		for j, s := range buf.stringSlice[:cap(buf.stringSlice)] {
			assert.Empty(t, s, "slot %d stringSlice[%d] still aliases input after Close", i, j)
		}
		for j, b := range buf.bytesSlice[:cap(buf.bytesSlice)] {
			assert.Nil(t, b, "slot %d bytesSlice[%d] still aliases input after Close", i, j)
		}
	}
}

func TestFastModeEmptyStringDoesNotAlias(t *testing.T) {
	// In DecoderModeFast, a zero-length string entry must come back as a
	// plain "" from both StringValue and StringValues, not an empty
	// unsafe.String whose data pointer still points into the input.
	msg := []byte{(1 << 3) | 2, 0x00}

	dec, err := NewDecoder(NewDef(1), WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)
	res, err := dec.Decode(msg)
	require.NoError(t, err)
	defer func() { _ = res.Close() }()

	s, err := res.StringValue(1)
	require.NoError(t, err)
	assert.Equal(t, "", s)
	assert.Nil(t, unsafe.StringData(s), "StringValue aliases the input for an empty string")

	ss, err := res.StringValues(1)
	require.NoError(t, err)
	require.Equal(t, []string{""}, ss)
	assert.Nil(t, unsafe.StringData(ss[0]), "StringValues aliases the input for an empty string")
}

func TestCloseAliasedFlag(t *testing.T) {
	// flagAliased marks exactly the fields whose fast-mode
	// StringValues/BytesValues caches alias the input; close() follows
	// cold.buffers only for those fields, then clears the flags.
	msg := []byte{
		(1 << 3) | 2, 0x02, 'a', 'b', // field 1: string "ab"
		(2 << 3) | 2, 0x02, 'x', 'y', // field 2: bytes "xy"
		(3 << 3) | 0, 0x2a, // field 3: varint 42
	}
	tags := []int{1, 2, 3}

	for _, tc := range []struct {
		name        string
		mode        csproto.DecoderMode
		access      func(*testing.T, *DecodeResult)
		wantAliased map[int]bool // tag -> flag; absent means false
	}{
		{"fast, no accessors", csproto.DecoderModeFast, func(*testing.T, *DecodeResult) {}, nil},
		{"fast, scalar accessors only", csproto.DecoderModeFast, func(t *testing.T, r *DecodeResult) {
			_, err := r.StringValue(1) // returns an alias but does not cache it
			require.NoError(t, err)
			_, err = r.BytesValue(2)
			require.NoError(t, err)
			_, err = r.UInt32Values(3) // cached, but numbers hold no pointers
			require.NoError(t, err)
		}, nil},
		{"fast, StringValues on field 1 only", csproto.DecoderModeFast, func(t *testing.T, r *DecodeResult) {
			_, err := r.StringValues(1)
			require.NoError(t, err)
		}, map[int]bool{1: true}},
		{"fast, BytesValues on field 2 only", csproto.DecoderModeFast, func(t *testing.T, r *DecodeResult) {
			_, err := r.BytesValues(2)
			require.NoError(t, err)
		}, map[int]bool{2: true}},
		{"fast, both", csproto.DecoderModeFast, func(t *testing.T, r *DecodeResult) {
			_, err := r.StringValues(1)
			require.NoError(t, err)
			_, err = r.BytesValues(2)
			require.NoError(t, err)
		}, map[int]bool{1: true, 2: true}},
		{"safe, StringValues and BytesValues", csproto.DecoderModeSafe, func(t *testing.T, r *DecodeResult) {
			_, err := r.StringValues(1) // copies; nothing aliases the input
			require.NoError(t, err)
			_, err = r.BytesValues(2)
			require.NoError(t, err)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := NewDecoder(NewDef(tags...), WithMode(tc.mode))
			require.NoError(t, err)
			res, err := dec.Decode(msg)
			require.NoError(t, err)

			fds := map[int]*FieldData{}
			for _, tag := range tags {
				idx, ok := res.lut.safeLookup(tag)
				require.True(t, ok)
				fds[tag] = &res.slab[idx]
				assert.Zero(t, fds[tag].flags, "tag %d: fresh decode must have no flags", tag)
			}

			tc.access(t, res)
			for _, tag := range tags {
				assert.Equal(t, tc.wantAliased[tag], fds[tag].flags&flagAliased != 0, "tag %d", tag)
			}

			shared := res.shared
			require.NoError(t, res.Close())
			for _, tag := range tags {
				fd := fds[tag]
				assert.Zero(t, fd.flags, "tag %d: Close must clear the flags", tag)
				if b := fd.cold.buffers; b != nil {
					for i, s := range b.stringSlice[:cap(b.stringSlice)] {
						assert.Empty(t, s, "tag %d stringSlice[%d] still aliases input", tag, i)
					}
					for i, v := range b.bytesSlice[:cap(b.bytesSlice)] {
						assert.Nil(t, v, "tag %d bytesSlice[%d] still aliases input", tag, i)
					}
				}
			}
			assert.Nil(t, shared.buf, "Close must release the input buffer")
		})
	}
}

func TestCloseRepeatedFlag(t *testing.T) {
	// flagRepeated is set only on fields that spilled into coldData.repeated;
	// close() resets their repeated entries so nothing leaks into the next decode.
	repeated := []byte{
		(1 << 3) | 0, 0x01, // field 1 = 1
		(1 << 3) | 0, 0x02, // field 1 = 2 (repeated)
		(2 << 3) | 0, 0x07, // field 2 = 7
	}
	single := []byte{
		(1 << 3) | 0, 0x05, // field 1 = 5
		(2 << 3) | 0, 0x08, // field 2 = 8
	}

	for _, mode := range []csproto.DecoderMode{csproto.DecoderModeSafe, csproto.DecoderModeFast} {
		t.Run(mode.String(), func(t *testing.T) {
			dec, err := NewDecoder(NewDef(1, 2), WithMode(mode))
			require.NoError(t, err)

			res, err := dec.Decode(repeated)
			require.NoError(t, err)
			idx1, ok := res.lut.safeLookup(1)
			require.True(t, ok)
			idx2, ok := res.lut.safeLookup(2)
			require.True(t, ok)
			fd1, fd2 := &res.slab[idx1], &res.slab[idx2]
			assert.NotZero(t, fd1.flags&flagRepeated, "field 1 occurs twice")
			assert.Zero(t, fd2.flags&flagRepeated, "field 2 occurs once")
			vals, err := res.UInt32Values(1)
			require.NoError(t, err)
			assert.Equal(t, []uint32{1, 2}, vals)

			require.NoError(t, res.Close())
			assert.Zero(t, fd1.flags, "Close must clear the flags")
			assert.Empty(t, fd1.cold.repeated, "Close must reset repeated entries")

			// The pooled result (likely the same object) must not carry the
			// old repeated entry into a decode where field 1 occurs once.
			res, err = dec.Decode(single)
			require.NoError(t, err)
			vals, err = res.UInt32Values(1)
			require.NoError(t, err)
			assert.Equal(t, []uint32{5}, vals)
			require.NoError(t, res.Close())
		})
	}
}

func TestAbsentFieldInvariant(t *testing.T) {
	// close() skips fields with !root.hasData(), so an absent field must
	// already be in its reset state: wt == -1 (set by clone() and restored
	// by close()), no flags, and a zero root. This must hold for fields that
	// have never been present as well as for fields present in an earlier
	// decode of the same pooled result.
	tags := []int{1, 2, 3, 4}

	// field 1: varint, field 2: repeated varint (flagRepeated),
	// field 3: string (flagAliased in fast mode via StringValues)
	msgA := []byte{
		(1 << 3) | 0, 0x01,
		(2 << 3) | 0, 0x02,
		(2 << 3) | 0, 0x03,
		(3 << 3) | 2, 0x02, 'a', 'b',
	}
	// field 4 only: fixed32
	msgB := []byte{
		(4 << 3) | 5, 0x01, 0x00, 0x00, 0x00,
	}

	for _, mode := range []csproto.DecoderMode{csproto.DecoderModeSafe, csproto.DecoderModeFast} {
		t.Run(mode.String(), func(t *testing.T) {
			dec, err := NewDecoder(NewDef(tags...), WithMode(mode))
			require.NoError(t, err)

			// Drive one pooled result through several decode/close cycles
			// directly so every cycle reuses the same object.
			res, ok := dec.pool.Get().(*DecodeResult)
			require.True(t, ok)

			fds := map[int]*FieldData{}
			for _, tag := range tags {
				idx, ok := res.lut.safeLookup(tag)
				require.True(t, ok)
				fds[tag] = &res.slab[idx]
			}

			assertAbsent := func(t *testing.T, stage string, absent ...int) {
				t.Helper()
				for _, tag := range absent {
					fd := fds[tag]
					assert.False(t, fd.hasData(), "%s: tag %d must be absent", stage, tag)
					assert.Equal(t, int8(-1), fd.wt, "%s: tag %d wt", stage, tag)
					assert.Zero(t, fd.flags, "%s: tag %d flags", stage, tag)
					assert.Equal(t, dataPtr{}, fd.root, "%s: tag %d root", stage, tag)
					assert.Empty(t, fd.cold.repeated, "%s: tag %d repeated", stage, tag)
				}
			}

			assertAbsent(t, "fresh clone", tags...)

			for cycle := 0; cycle < 2; cycle++ {
				stage := func(s string) string { return fmt.Sprintf("cycle %d: %s", cycle, s) }

				require.NoError(t, res.decode(msgA))
				assert.NotZero(t, fds[2].flags&flagRepeated, "field 2 occurs twice")
				_, err = res.StringValues(3)
				require.NoError(t, err)
				// Field 4 has never been present in this result before
				// msgB on cycle 0; afterwards it was present and reset.
				assertAbsent(t, stage("decode msgA"), 4)
				_, err = res.Fixed32Values(4)
				assert.ErrorIs(t, err, ErrTagNotFound)

				res.close()
				assertAbsent(t, stage("close msgA"), tags...)

				require.NoError(t, res.decode(msgB))
				// Fields 1-3 were present in the previous decode.
				assertAbsent(t, stage("decode msgB"), 1, 2, 3)
				_, err = res.UInt32Values(1)
				assert.ErrorIs(t, err, ErrTagNotFound)
				_, err = res.StringValues(3)
				assert.ErrorIs(t, err, ErrTagNotFound)
				vals, err := res.Fixed32Values(4)
				require.NoError(t, err)
				assert.Equal(t, []uint32{1}, vals)

				res.close()
				assertAbsent(t, stage("close msgB"), tags...)
			}
		})
	}
}

func TestFieldDataLayout(t *testing.T) {
	// FieldData is the hot per-field struct; keep it at 24 bytes with the
	// wire type and flags packed ahead of root. coldData stays at 40 bytes.
	if strconv.IntSize < 64 {
		t.Skip("sizes below are for 64-bit platforms")
	}
	assert.Equal(t, uintptr(24), unsafe.Sizeof(FieldData{}))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(FieldData{}.wt))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(FieldData{}.flags))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(FieldData{}.root))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(FieldData{}.cold))
	assert.Equal(t, uintptr(40), unsafe.Sizeof(coldData{}))
}

func TestFieldDataStableAddress(t *testing.T) {
	// GetFieldData and Range hand out &slab[slot]. The slab is allocated once
	// per result and never reallocated, so a field's address must be the same
	// in every decode of the same pooled result.
	dec, err := NewDecoder(NewDef(1, 2), WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)
	data := []byte{(1 << 3) | 0, 0x05, (2 << 3) | 0, 0x07} // field 1 = 5, field 2 = 7

	// Drive one pooled result through two decode/close cycles directly, so
	// sync.Pool can't substitute a different object between them.
	res, ok := dec.pool.Get().(*DecodeResult)
	require.True(t, ok)

	var first [2]*FieldData
	for cycle := range 2 {
		require.NoError(t, res.decode(data))
		for i, tag := range []int{1, 2} {
			slot, ok := res.lut.safeLookup(tag)
			require.True(t, ok)
			fd, err := res.GetFieldData(tag)
			require.NoError(t, err)
			assert.Same(t, &res.slab[slot], fd, "cycle %d: GetFieldData(%d) must return &slab[slot]", cycle, tag)
			if cycle == 0 {
				first[i] = fd
			} else {
				assert.Same(t, first[i], fd, "tag %d: address must survive close and re-decode", tag)
			}
		}
		res.Range(func(tag int, fd *FieldData) bool {
			slot, _ := res.lut.safeLookup(tag)
			assert.Same(t, &res.slab[slot], fd, "cycle %d: Range(%d) must pass &slab[slot]", cycle, tag)
			return true
		})
		res.close()
	}
}

// bufLimitMsg: field 1 = 5 varints (repeated), field 2 = 1 varint, field 4 = 5 nested
// messages (each {field 1: 1}), so repeated entries, cached XxxValues slices and closers
// can all grow past a small WithMaxBufferSize limit.
var bufLimitMsg = func() []byte {
	var b []byte
	for i := 0; i < 5; i++ {
		b = append(b, (1<<3)|0, byte(i+1))
	}
	b = append(b, (2<<3)|0, 0x07)
	for i := 0; i < 5; i++ {
		b = append(b, (4<<3)|2, 0x02, (1<<3)|0, 0x01)
	}
	return b
}()

func bufLimitDef() Def {
	def := NewDef(1, 2)
	_ = def.NestedTag(4, 1)
	return def
}

func fieldByTag(t *testing.T, r *DecodeResult, tag int) *FieldData {
	t.Helper()
	idx, ok := r.lut.safeLookup(tag)
	require.True(t, ok)
	return &r.slab[idx]
}

func TestCloseBufferLimitFlag(t *testing.T) {
	// WithMaxBufferSize: only fields whose slices grew past the limit are
	// flagged (flagTrunc) and truncated by close(); others are untouched.
	const limit = 2
	for _, mode := range []csproto.DecoderMode{csproto.DecoderModeSafe, csproto.DecoderModeFast} {
		t.Run(mode.String(), func(t *testing.T) {
			dec, err := NewDecoder(bufLimitDef(), WithMode(mode), WithMaxBufferSize(limit))
			require.NoError(t, err)
			res, err := dec.Decode(bufLimitMsg)
			require.NoError(t, err)

			fd1, fd2 := fieldByTag(t, res, 1), fieldByTag(t, res, 2)
			assert.NotZero(t, fd1.flags&flagTrunc, "field 1's repeated entries exceed the limit")
			assert.Zero(t, fd2.flags&flagTrunc, "field 2 is under the limit")

			v1, err := res.UInt32Values(1)
			require.NoError(t, err)
			assert.Len(t, v1, 5)
			v2, err := res.UInt32Values(2)
			require.NoError(t, err)
			assert.Equal(t, []uint32{7}, v2)
			nested, err := res.NestedResults(4)
			require.NoError(t, err)
			require.Len(t, nested, 5)
			require.Greater(t, cap(res.closers), limit)

			var fd2Backing *uint32
			if b := fd2.cold.buffers; b != nil {
				fd2Backing = unsafe.SliceData(b.uint32Slice)
			}

			require.NoError(t, res.Close())

			assert.Zero(t, fd1.flags, "Close must clear flags")
			assert.LessOrEqual(t, cap(fd1.cold.repeated), limit)
			assert.LessOrEqual(t, cap(res.closers), limit, "closers over the limit must be truncated")
			if b := fd1.cold.buffers; b != nil { // fast mode
				assert.LessOrEqual(t, cap(b.uint32Slice), limit)
			}
			if b := fd2.cold.buffers; b != nil { // fast mode: untouched field keeps its backing array
				assert.Same(t, fd2Backing, unsafe.SliceData(b.uint32Slice))
			}
		})
	}

	t.Run("unlimited never flags", func(t *testing.T) {
		dec, err := NewDecoder(bufLimitDef(), WithMode(csproto.DecoderModeFast))
		require.NoError(t, err)
		res, err := dec.Decode(bufLimitMsg)
		require.NoError(t, err)
		_, err = res.UInt32Values(1)
		require.NoError(t, err)
		fd1 := fieldByTag(t, res, 1)
		assert.NotZero(t, fd1.flags&flagRepeated)
		assert.Zero(t, fd1.flags&flagTrunc)
		require.NoError(t, res.Close())
	})
}

func TestCloseBufferFilterFunc(t *testing.T) {
	// WithBufferFilterFunc keeps the full walk: the filter sees the
	// result-wide max capacity and truncates every field, including one that
	// grew in an earlier cycle and isn't used in the current one.
	limit := -1 // first cycle: keep everything
	var seen []int
	dec, err := NewDecoder(bufLimitDef(), WithMode(csproto.DecoderModeFast),
		WithBufferFilterFunc(func(c int) int { seen = append(seen, c); return limit }))
	require.NoError(t, err)

	res, err := dec.Decode(bufLimitMsg)
	require.NoError(t, err)
	_, err = res.UInt32Values(1)
	require.NoError(t, err)
	fd1 := fieldByTag(t, res, 1)
	require.NoError(t, res.Close())
	require.NotEmpty(t, seen)
	assert.GreaterOrEqual(t, seen[len(seen)-1], 5, "filter receives the result-wide max capacity")
	require.GreaterOrEqual(t, cap(fd1.cold.buffers.uint32Slice), 5, "limit -1: nothing truncated")

	// Second cycle: field 1 is absent, so it isn't touched — the filter walk
	// must still truncate its buffers from the first cycle.
	limit = 1
	res2, err := dec.Decode([]byte{(2 << 3) | 0, 0x07})
	require.NoError(t, err)
	if res2 != res {
		require.NoError(t, res2.Close())
		t.Skip("pool returned a different result; cannot observe the earlier cycle's buffers")
	}
	require.NoError(t, res2.Close())
	assert.LessOrEqual(t, cap(fd1.cold.buffers.uint32Slice), 1)
	assert.LessOrEqual(t, cap(fd1.cold.repeated), 1)
}

func TestDeprecatedDecodeNestedDecodersUnlimitedMaxBuffer(t *testing.T) {
	// The deprecated Decode must not leave nested decoders with maxBuffer=0,
	// which would act like WithMaxBufferSize(0) and truncate every nested
	// repeated slice on close.
	def := NewDef()
	def.NestedTag(1).Tags(2)
	data := []byte{0x0a, 0x02, 0x10, 0x01} // tag 1 { tag 2: 1 }

	res, err := Decode(data, def)
	require.NoError(t, err)
	assert.Equal(t, math.MaxInt, res.shared.maxBuffer)

	nested := 0
	for _, d := range res.nestedDecoders {
		if d == nil {
			continue
		}
		nested++
		assert.Equal(t, -1, d.maxBuffer, "nested decoder must inherit unlimited max buffer")
	}
	require.Equal(t, 1, nested)
}

// assertClosersCleared checks the whole closers backing array (not just
// [:len]) holds no pointers to nested results already returned to a pool.
func assertClosersCleared(t *testing.T, r *DecodeResult) {
	t.Helper()
	for i, c := range r.closers[:cap(r.closers)] {
		assert.Nil(t, c, "closers[%d] still points at a pooled nested result", i)
	}
}

func TestCloseClearsClosers(t *testing.T) {
	def := NewDef()
	def.NestedTag(1).Tags(2)
	dec, err := NewDecoder(def)
	require.NoError(t, err)

	// tag 1 { tag 2: 1 }, tag 1 { tag 2: 2 }
	res, err := dec.Decode([]byte{0x0a, 0x02, 0x10, 0x01, 0x0a, 0x02, 0x10, 0x02})
	require.NoError(t, err)
	nested, err := res.NestedResults(1)
	require.NoError(t, err)
	require.Len(t, nested, 2)
	require.Len(t, res.closers, 2)

	require.NoError(t, res.Close())
	assert.Empty(t, res.closers)
	assertClosersCleared(t, res)
}

func TestDeprecatedDecodeCopyDoubleClose(t *testing.T) {
	// The deprecated Decode returns a DecodeResult by value, so copies share
	// the closers backing array. Closing one copy clears the shared entries;
	// closing the other must neither nil-deref nor re-close (and re-pool) the
	// already-closed nested child.
	def := NewDef()
	def.NestedTag(1).Tags(2)
	data := []byte{0x0a, 0x02, 0x10, 0x01} // tag 1 { tag 2: 1 }

	res, err := Decode(data, def)
	require.NoError(t, err)
	_, err = res.NestedResult(1)
	require.NoError(t, err)
	require.Len(t, res.closers, 1)

	res2 := res
	require.NoError(t, res.Close())
	require.NotPanics(t, func() { _ = res2.Close() })
	assertClosersCleared(t, &res2)
}

func TestNestedResultsErrorClearsClosers(t *testing.T) {
	def := NewDef()
	def.NestedTag(1).Tags(2)
	dec, err := NewDecoder(def)
	require.NoError(t, err)

	// tag 1 { tag 2: 1 }, tag 1 { <truncated tag varint> }
	res, err := dec.Decode([]byte{0x0a, 0x02, 0x10, 0x01, 0x0a, 0x01, 0x80})
	require.NoError(t, err)
	defer res.Close()

	_, err = res.NestedResults(1)
	require.Error(t, err)
	assert.Empty(t, res.closers, "rollback must remove the decoded children")
	require.Positive(t, cap(res.closers), "first child was appended before the error")
	assertClosersCleared(t, res)
}

func TestNestedResultsWireTypeMismatch(t *testing.T) {
	// A nested tag encoded with a non-length-delimited wire type must be
	// rejected with a WireTypeMismatchError by both NestedResult and
	// NestedResults, rather than decoding the raw scalar bytes as a message.
	for _, mode := range []csproto.DecoderMode{csproto.DecoderModeSafe, csproto.DecoderModeFast} {
		t.Run(mode.String(), func(t *testing.T) {
			def := NewDef()
			def.NestedTag(1).Tags(2)
			dec, err := NewDecoder(def, WithMode(mode))
			require.NoError(t, err)

			// tag 1, varint 150
			res, err := dec.Decode([]byte{0x08, 0x96, 0x01})
			require.NoError(t, err)
			defer res.Close()

			var mismatch *WireTypeMismatchError

			_, err = res.NestedResult(1)
			assert.ErrorAs(t, err, &mismatch, "NestedResult should return a WireTypeMismatchError")

			results, err := res.NestedResults(1)
			assert.ErrorAs(t, err, &mismatch, "NestedResults should return a WireTypeMismatchError")
			assert.Nil(t, results)
			assert.Empty(t, res.closers)
		})
	}
}

func TestFastModeSliceValuesErrorKeepsBuffer(t *testing.T) {
	// A failing fast-mode XxxValues call must keep its pooled reuse slice
	// instead of overwriting it with nil, or every later call allocates.
	dec, err := NewDecoder(NewDef(1), WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	// tag 1, length-delimited, packed varints {1, <truncated>}
	res, err := dec.Decode([]byte{0x0a, 0x02, 0x01, 0x80})
	require.NoError(t, err)
	defer res.Close()
	fd := fieldByTag(t, res, 1)

	s, err := fd.Int64Values()
	require.Error(t, err)
	assert.Nil(t, s, "callers still get nil on error")
	require.NotNil(t, fd.cold.buffers.int64Slice, "reuse slice must survive an error")
	assert.Positive(t, cap(fd.cold.buffers.int64Slice))

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = fd.Int64Values()
	})
	assert.Zero(t, allocs, "repeated failing calls must reuse the buffer")
}

func TestFastModeSliceValuesReuseAfterError(t *testing.T) {
	// Int32Values and SInt32Values share int32Slice. The second varint
	// (0xFFFFFFFF) overflows int32 but is a valid zigzag32 value, so
	// Int32Values fails part-way and SInt32Values succeeds.
	dec, err := NewDecoder(NewDef(1), WithMode(csproto.DecoderModeFast))
	require.NoError(t, err)

	res, err := dec.Decode([]byte{0x0a, 0x06, 0x01, 0xff, 0xff, 0xff, 0xff, 0x0f})
	require.NoError(t, err)
	defer res.Close()
	fd := fieldByTag(t, res, 1)

	// Warm the shared slot with a successful call so it is big enough.
	warm, err := fd.SInt32Values()
	require.NoError(t, err)
	backing := unsafe.SliceData(warm)

	_, err = fd.Int32Values()
	require.ErrorIs(t, err, csproto.ErrValueOverflow)
	require.NotNil(t, fd.cold.buffers.int32Slice, "reuse slice must survive an error")
	assert.Same(t, backing, unsafe.SliceData(fd.cold.buffers.int32Slice), "failed call must keep the backing array")

	got, err := fd.SInt32Values()
	require.NoError(t, err)
	assert.Equal(t, []int32{-1, math.MinInt32}, got)
	assert.Same(t, backing, unsafe.SliceData(got), "call after a failure must reuse the backing array")
}
