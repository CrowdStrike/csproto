package lazyproto

import (
	"sync/atomic"
	"testing"

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
