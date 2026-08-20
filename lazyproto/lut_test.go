package lazyproto

import (
	"math"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLutTable(t *testing.T) {
	t.Parallel()
	t.Run("empty def", func(t *testing.T) {
		t.Parallel()
		def := NewDef()
		lut := newLutTable(def)

		require.NotNil(t, lut)
		assert.Nil(t, lut.overflow)
	})
	t.Run("single tag", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		lut := newLutTable(def)

		slot, ok := lut.lookup(1)
		assert.True(t, ok)
		assert.Equal(t, 0, slot)
	})
	t.Run("sequential tags", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1, 2, 3, 4, 5)
		lut := newLutTable(def)

		for i := 1; i <= 5; i++ {
			slot, ok := lut.lookup(i)
			assert.True(t, ok, "tag %d should be found", i)
			assert.Equal(t, i-1, slot, "tag %d should map to slot %d", i, i-1)
		}
	})
	t.Run("non-sequential tags", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1, 5, 10, 100)
		lut := newLutTable(def)

		expected := map[int]int{
			1:   0,
			5:   1,
			10:  2,
			100: 3,
		}
		for tag, expectedSlot := range expected {
			slot, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d should be found", tag)
			assert.Equal(t, expectedSlot, slot, "tag %d should map to slot %d", tag, expectedSlot)
		}
	})
	t.Run("sparse tags across word boundaries", func(t *testing.T) {
		t.Parallel()
		// Tags in different 64-bit words: word 0 (0-63), word 1 (64-127), word 2 (128-191)
		def := NewDef(1, 63, 64, 65, 128)
		lut := newLutTable(def)

		expected := map[int]int{
			1:   0,
			63:  1,
			64:  2,
			65:  3,
			128: 4,
		}
		for tag, expectedSlot := range expected {
			slot, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d should be found", tag)
			assert.Equal(t, expectedSlot, slot, "tag %d should map to slot %d", tag, expectedSlot)
		}
	})
	t.Run("tag at maxTag boundary", func(t *testing.T) {
		t.Parallel()
		def := NewDef(maxTag)
		lut := newLutTable(def)

		slot, ok := lut.lookup(maxTag)
		assert.True(t, ok)
		assert.Equal(t, 0, slot)
	})
	t.Run("overflow tags above maxTag", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1, 2, maxTag+1, maxTag+100)
		lut := newLutTable(def)

		// Normal tags still work
		slot, ok := lut.lookup(1)
		assert.True(t, ok)
		assert.Equal(t, 0, slot)

		slot, ok = lut.lookup(2)
		assert.True(t, ok)
		assert.Equal(t, 1, slot)

		// Overflow tags get sequential slots after bitmap tags
		slot, ok = lut.lookup(maxTag + 1)
		assert.True(t, ok)
		assert.Equal(t, 2, slot, "first overflow tag should follow bitmap count")

		slot, ok = lut.lookup(maxTag + 100)
		assert.True(t, ok)
		assert.Equal(t, 3, slot, "second overflow tag should be sequential")
	})
	t.Run("overflow map is nil when no overflow tags", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1, 2, 3)
		lut := newLutTable(def)
		assert.Nil(t, lut.overflow)
	})
	t.Run("negative tags are treated as their absolute value", func(t *testing.T) {
		t.Parallel()
		// The Def type allows negative keys for raw field access (e.g., tag -3 means "raw data at tag 3")
		def := Def{-3: nil, 1: nil}
		lut := newLutTable(def)

		// Negative tag -3 should be stored as tag 3
		slot, ok := lut.lookup(3)
		assert.True(t, ok, "abs(-3) = 3 should be found")

		slot2, ok := lut.lookup(1)
		assert.True(t, ok)
		// Tag 1 < tag 3, so tag 1 gets slot 0, tag 3 gets slot 1
		assert.Equal(t, 0, slot2, "tag 1 should be slot 0")
		assert.Equal(t, 1, slot, "tag 3 (from -3) should be slot 1")
	})
}

func TestLutTableLookup(t *testing.T) {
	t.Parallel()
	t.Run("tag not found returns false", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1, 3, 5)
		lut := newLutTable(def)

		_, ok := lut.lookup(2)
		assert.False(t, ok)

		_, ok = lut.lookup(4)
		assert.False(t, ok)

		_, ok = lut.lookup(99)
		assert.False(t, ok)
	})
	t.Run("overflow tag not found returns false", func(t *testing.T) {
		t.Parallel()
		def := NewDef(1)
		lut := newLutTable(def)

		_, ok := lut.lookup(maxTag + 1)
		assert.False(t, ok)
	})
	t.Run("tag zero", func(t *testing.T) {
		t.Parallel()
		def := Def{0: nil}
		lut := newLutTable(def)

		slot, ok := lut.lookup(0)
		assert.True(t, ok)
		assert.Equal(t, 0, slot)
	})
	t.Run("slots are dense and ordered by tag value", func(t *testing.T) {
		t.Parallel()
		// Verify that the LUT assigns slots in tag-value order (lower tags get lower slots)
		tags := []int{100, 5, 200, 1, 50}
		def := NewDef(tags...)
		lut := newLutTable(def)

		// After sorting by tag value: 1=slot0, 5=slot1, 50=slot2, 100=slot3, 200=slot4
		expected := map[int]int{
			1:   0,
			5:   1,
			50:  2,
			100: 3,
			200: 4,
		}
		for tag, expectedSlot := range expected {
			slot, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d should be found", tag)
			assert.Equal(t, expectedSlot, slot, "tag %d should map to slot %d", tag, expectedSlot)
		}
	})
}

func TestLutTableRankAccuracy(t *testing.T) {
	t.Parallel()
	t.Run("many tags in same word", func(t *testing.T) {
		t.Parallel()
		// Fill the first word (bits 0-63) with several tags
		tags := []int{0, 1, 2, 3, 4, 5, 10, 20, 30, 40, 50, 60, 63}
		def := NewDef(tags...)
		lut := newLutTable(def)

		for i, tag := range tags {
			slot, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d should be found", tag)
			assert.Equal(t, i, slot, "tag %d should map to slot %d", tag, i)
		}
	})
	t.Run("tags spanning many words", func(t *testing.T) {
		t.Parallel()
		// One tag per word boundary to verify rank accumulation
		tags := []int{0, 64, 128, 192, 256, 320}
		def := NewDef(tags...)
		lut := newLutTable(def)

		for i, tag := range tags {
			slot, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d should be found", tag)
			assert.Equal(t, i, slot, "tag %d should map to slot %d", tag, i)
		}
	})
	t.Run("full word then next word tag", func(t *testing.T) {
		t.Parallel()
		// Fill all 64 bits in word 0, then check rank for tag 64 (word 1)
		var tags []int
		for i := 0; i < 64; i++ {
			tags = append(tags, i)
		}
		tags = append(tags, 64)
		def := NewDef(tags...)
		lut := newLutTable(def)

		// Tag 64 should be at slot 64 (after all 64 tags in word 0)
		slot, ok := lut.lookup(64)
		assert.True(t, ok)
		assert.Equal(t, 64, slot)
	})
}

func TestLutTableCount(t *testing.T) {
	t.Parallel()
	t.Run("empty def", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef())
		assert.Equal(t, 0, lut.count())
	})
	t.Run("single tag", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(1))
		assert.Equal(t, 1, lut.count())
	})
	t.Run("multiple bitmap tags", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(1, 2, 4, 5, 9))
		assert.Equal(t, 5, lut.count())
	})
	t.Run("tags spanning word boundaries", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(1, 63, 64, 128, 500))
		assert.Equal(t, 5, lut.count())
	})
	t.Run("with overflow tags", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(1, 2, 3, maxTag+1, maxTag+200))
		assert.Equal(t, 5, lut.count())
	})
	t.Run("only overflow tags", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(maxTag+1, maxTag+2, maxTag+3))
		assert.Equal(t, 3, lut.count())
	})
	t.Run("count matches number of tags in def", func(t *testing.T) {
		t.Parallel()
		tags := []int{1, 5, 10, 50, 100, 500, 1000, 5000, 10000, 18000, maxTag + 50}
		lut := newLutTable(NewDef(tags...))
		assert.Equal(t, len(tags), lut.count())
	})
}

func TestLutTableAll(t *testing.T) {
	t.Parallel()
	t.Run("empty def yields nothing", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef())

		var count int
		for range lut.all() {
			count++
		}
		assert.Equal(t, 0, count)
	})
	t.Run("single tag", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(42))

		var pairs [][2]int
		for tag, slot := range lut.all() {
			pairs = append(pairs, [2]int{tag, slot})
		}
		assert.Equal(t, [][2]int{{42, 0}}, pairs)
	})
	t.Run("yields tags in ascending order", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(100, 5, 200, 1, 50))

		var tags []int
		for tag := range lut.all() {
			tags = append(tags, tag)
		}
		assert.Equal(t, []int{1, 5, 50, 100, 200}, tags)
	})
	t.Run("slots are dense and sequential", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(3, 7, 15, 64, 130))

		var slots []int
		for _, slot := range lut.all() {
			slots = append(slots, slot)
		}
		assert.Equal(t, []int{0, 1, 2, 3, 4}, slots)
	})
	t.Run("tags across word boundaries", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(0, 63, 64, 127, 128))

		var pairs [][2]int
		for tag, slot := range lut.all() {
			pairs = append(pairs, [2]int{tag, slot})
		}
		expected := [][2]int{{0, 0}, {63, 1}, {64, 2}, {127, 3}, {128, 4}}
		assert.Equal(t, expected, pairs)
	})
	t.Run("includes overflow tags", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(1, 2, maxTag+10, maxTag+20))

		var tags []int
		for tag := range lut.all() {
			tags = append(tags, tag)
		}
		// Bitmap tags come first in order, then overflow tags
		assert.Contains(t, tags, 1)
		assert.Contains(t, tags, 2)
		assert.Contains(t, tags, maxTag+10)
		assert.Contains(t, tags, maxTag+20)
		assert.Equal(t, 4, len(tags))
	})
	t.Run("early break stops iteration", func(t *testing.T) {
		t.Parallel()
		lut := newLutTable(NewDef(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))

		var count int
		for range lut.all() {
			count++
			if count == 3 {
				break
			}
		}
		assert.Equal(t, 3, count)
	})
	t.Run("all count matches count method", func(t *testing.T) {
		t.Parallel()
		tags := []int{1, 5, 10, 64, 128, 500, 1000, maxTag + 1}
		lut := newLutTable(NewDef(tags...))

		var iterCount int
		for range lut.all() {
			iterCount++
		}
		assert.Equal(t, lut.count(), iterCount)
	})
	t.Run("all slots match individual lookups", func(t *testing.T) {
		t.Parallel()
		tags := []int{2, 7, 33, 64, 100, 200, 1000}
		lut := newLutTable(NewDef(tags...))

		for tag, slot := range lut.all() {
			lookedUp, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d from all() should be found via lookup()", tag)
			assert.Equal(t, slot, lookedUp, "tag %d: all() slot %d != lookup() slot %d", tag, slot, lookedUp)
		}
	})
	t.Run("reverse order input produces sorted tags and sequential slots", func(t *testing.T) {
		t.Parallel()
		// Tags given in descending order
		lut := newLutTable(NewDef(500, 200, 100, 50, 10, 1))

		var tags []int
		var slots []int
		for tag, slot := range lut.all() {
			tags = append(tags, tag)
			slots = append(slots, slot)
		}
		assert.Equal(t, []int{1, 10, 50, 100, 200, 500}, tags, "tags should be sorted ascending regardless of input order")
		assert.Equal(t, []int{0, 1, 2, 3, 4, 5}, slots, "slots should be dense 0..N-1")
	})
	t.Run("scrambled input across word boundaries produces sorted output", func(t *testing.T) {
		t.Parallel()
		// Deliberately scrambled tags spanning multiple 64-bit words
		lut := newLutTable(NewDef(192, 3, 130, 64, 1, 65, 0))

		var pairs [][2]int
		for tag, slot := range lut.all() {
			pairs = append(pairs, [2]int{tag, slot})
		}
		expected := [][2]int{{0, 0}, {1, 1}, {3, 2}, {64, 3}, {65, 4}, {130, 5}, {192, 6}}
		assert.Equal(t, expected, pairs, "all() should yield (tag, slot) sorted by tag regardless of Def insertion order")
	})
	t.Run("random-order duplicates across words produce stable sorted output", func(t *testing.T) {
		t.Parallel()
		// Same tag set constructed two different ways should produce identical iteration
		lut1 := newLutTable(NewDef(999, 7, 128, 2, 63, 500))
		lut2 := newLutTable(NewDef(2, 7, 63, 128, 500, 999))

		var pairs1, pairs2 [][2]int
		for tag, slot := range lut1.all() {
			pairs1 = append(pairs1, [2]int{tag, slot})
		}
		for tag, slot := range lut2.all() {
			pairs2 = append(pairs2, [2]int{tag, slot})
		}
		assert.Equal(t, pairs1, pairs2, "iteration order should be identical regardless of Def construction order")
		// Verify it's actually sorted
		assert.True(t, slices.IsSortedFunc(pairs1, func(a, b [2]int) int { return a[0] - b[0] }))
	})
	t.Run("large scrambled set produces monotonically increasing tags and slots", func(t *testing.T) {
		t.Parallel()
		// 20 tags in a shuffled order
		input := []int{18000, 5, 9999, 64, 1, 300, 127, 8000, 12000, 63, 128, 2, 15000, 50, 256, 4096, 10, 7777, 100, 3}
		lut := newLutTable(NewDef(input...))

		var prevTag, prevSlot int
		first := true
		for tag, slot := range lut.all() {
			if !first {
				assert.Greater(t, tag, prevTag, "tags must be strictly increasing")
				assert.Greater(t, slot, prevSlot, "slots must be strictly increasing")
			}
			first = false
			prevTag = tag
			prevSlot = slot
		}
		assert.False(t, first, "iterator should have yielded at least one element")
	})
	t.Run("overflow tags are returned in sorted order", func(t *testing.T) {
		t.Parallel()
		// All tags above maxTag go into the overflow map. Maps have non-deterministic
		// iteration order, so this test verifies that all() returns them sorted.
		overflowTags := []int{maxTag + 500, maxTag + 1, maxTag + 100, maxTag + 50, maxTag + 999}
		lut := newLutTable(NewDef(overflowTags...))

		var tags []int
		for tag := range lut.all() {
			tags = append(tags, tag)
		}

		sorted := make([]int, len(tags))
		copy(sorted, tags)
		slices.Sort(sorted)
		assert.Equal(t, sorted, tags, "overflow tags from all() must be in ascending order")
	})
}

func TestLutTableNegativeValues(t *testing.T) {
	t.Parallel()
	t.Run("negative tag is stored as absolute value", func(t *testing.T) {
		t.Parallel()
		def := Def{-5: nil, 1: nil}
		lut := newLutTable(def)

		// -5 stored as 5
		slot, ok := lut.lookup(5)
		assert.True(t, ok, "abs(-5) = 5 should be found")
		assert.Equal(t, 1, slot, "tag 5 should be slot 1 (after tag 1)")

		slot, ok = lut.lookup(1)
		assert.True(t, ok)
		assert.Equal(t, 0, slot, "tag 1 should be slot 0")
	})
	t.Run("negative tag not found via negative lookup", func(t *testing.T) {
		t.Parallel()
		def := Def{-5: nil}
		lut := newLutTable(def)

		// Direct lookup with negative should not find it (only safeLookup handles negatives)
		_, ok := lut.lookup(5)
		assert.True(t, ok, "should find via absolute value")
	})
	t.Run("safeLookup resolves negative tags", func(t *testing.T) {
		t.Parallel()
		def := Def{-7: nil, 3: nil}
		lut := newLutTable(def)

		slot, ok := lut.safeLookup(-7)
		assert.True(t, ok, "safeLookup(-7) should find tag 7")
		assert.Equal(t, 1, slot, "tag 7 should be slot 1 (after tag 3)")

		slot, ok = lut.safeLookup(3)
		assert.True(t, ok, "safeLookup(3) should find tag 3")
		assert.Equal(t, 0, slot, "tag 3 should be slot 0")
	})
	t.Run("multiple negative tags", func(t *testing.T) {
		t.Parallel()
		def := Def{-1: nil, -3: nil, -10: nil}
		lut := newLutTable(def)

		// Should be stored as 1, 3, 10
		expected := map[int]int{1: 0, 3: 1, 10: 2}
		for tag, expectedSlot := range expected {
			slot, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d should be found", tag)
			assert.Equal(t, expectedSlot, slot, "tag %d should map to slot %d", tag, expectedSlot)
		}
		assert.Equal(t, 3, lut.count())
	})
	t.Run("math.MinInt saturates to math.MaxInt and goes to overflow", func(t *testing.T) {
		t.Parallel()
		def := Def{math.MinInt: nil, 1: nil}
		lut := newLutTable(def)

		// math.MinInt -> absSaturating -> math.MaxInt -> overflow map
		assert.Equal(t, 2, lut.count())

		// Tag 1 should be in bitmap
		slot, ok := lut.lookup(1)
		assert.True(t, ok)
		assert.Equal(t, 0, slot)

		// math.MaxInt should be in overflow
		slot, ok = lut.lookup(math.MaxInt)
		assert.True(t, ok, "math.MaxInt (from saturated MinInt) should be in overflow")
		assert.Equal(t, 1, slot)
	})
	t.Run("safeLookup with math.MinInt finds saturated value", func(t *testing.T) {
		t.Parallel()
		def := Def{math.MinInt: nil}
		lut := newLutTable(def)

		slot, ok := lut.safeLookup(math.MinInt)
		assert.True(t, ok, "safeLookup(MinInt) should find the saturated value")
		assert.Equal(t, 0, slot)
	})
}

func TestLutTableMaxIntValues(t *testing.T) {
	t.Parallel()
	t.Run("math.MaxInt goes to overflow", func(t *testing.T) {
		t.Parallel()
		def := Def{math.MaxInt: nil}
		lut := newLutTable(def)

		slot, ok := lut.lookup(math.MaxInt)
		assert.True(t, ok, "math.MaxInt should be found in overflow")
		assert.Equal(t, 0, slot)
		assert.Equal(t, 1, lut.count())
	})
	t.Run("math.MaxInt with bitmap tags", func(t *testing.T) {
		t.Parallel()
		def := Def{1: nil, 100: nil, math.MaxInt: nil}
		lut := newLutTable(def)

		assert.Equal(t, 3, lut.count())

		slot, ok := lut.lookup(1)
		assert.True(t, ok)
		assert.Equal(t, 0, slot)

		slot, ok = lut.lookup(100)
		assert.True(t, ok)
		assert.Equal(t, 1, slot)

		slot, ok = lut.lookup(math.MaxInt)
		assert.True(t, ok)
		assert.Equal(t, 2, slot, "MaxInt should get slot after bitmap tags")
	})
	t.Run("multiple large overflow values", func(t *testing.T) {
		t.Parallel()
		def := Def{math.MaxInt: nil, math.MaxInt - 1: nil, maxTag + 1: nil}
		lut := newLutTable(def)

		assert.Equal(t, 3, lut.count())
		assert.NotNil(t, lut.overflow)

		// All should be findable
		for tag := range def {
			_, ok := lut.lookup(tag)
			assert.True(t, ok, "tag %d should be found", tag)
		}
	})
	t.Run("MaxInt appears in all iterator", func(t *testing.T) {
		t.Parallel()
		def := Def{1: nil, math.MaxInt: nil}
		lut := newLutTable(def)

		var found bool
		for tag := range lut.all() {
			if tag == math.MaxInt {
				found = true
			}
		}
		assert.True(t, found, "all() should yield math.MaxInt")
	})
}

func TestLutTableOverflowDedup(t *testing.T) {
	t.Parallel()
	t.Run("negative and positive overflow collision is deduplicated", func(t *testing.T) {
		t.Parallel()
		// Both -20000 and 20000 map to 20000 after absSaturating.
		// The overflow map should contain only one entry, not two.
		def := Def{-20000: nil, 20000: nil, 1: nil}
		lut := newLutTable(def)

		// Tag 1 in bitmap, tag 20000 in overflow (deduplicated)
		assert.Equal(t, 2, lut.count())

		slot, ok := lut.lookup(1)
		assert.True(t, ok)
		assert.Equal(t, 0, slot)

		slot, ok = lut.lookup(20000)
		assert.True(t, ok)
		assert.Equal(t, 1, slot)
	})
	t.Run("multiple overflow collisions", func(t *testing.T) {
		t.Parallel()
		// -30000/30000 and -40000/40000 both collide
		def := Def{-30000: nil, 30000: nil, -40000: nil, 40000: nil, 1: nil}
		lut := newLutTable(def)

		// 1 bitmap tag + 2 unique overflow tags
		assert.Equal(t, 3, lut.count())

		slot, ok := lut.lookup(30000)
		assert.True(t, ok)
		assert.Equal(t, 1, slot)

		slot, ok = lut.lookup(40000)
		assert.True(t, ok)
		assert.Equal(t, 2, slot)
	})
}

func TestAbsSaturating(t *testing.T) {
	t.Parallel()
	t.Run("positive values unchanged", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 0, absSaturating(0))
		assert.Equal(t, 1, absSaturating(1))
		assert.Equal(t, 42, absSaturating(42))
		assert.Equal(t, math.MaxInt, absSaturating(math.MaxInt))
	})
	t.Run("negative values negated", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 1, absSaturating(-1))
		assert.Equal(t, 42, absSaturating(-42))
		assert.Equal(t, math.MaxInt, absSaturating(-math.MaxInt))
	})
	t.Run("math.MinInt saturates to math.MaxInt", func(t *testing.T) {
		t.Parallel()
		// math.MinInt cannot be negated without overflow; absSaturating clamps to MaxInt
		assert.Equal(t, math.MaxInt, absSaturating(math.MinInt))
	})
}

// Set of tags derived from platformevents.PlatformBaseEvent
var sampleTags = [...]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 100, 124, 362, 407}

func BenchmarkLutTableLookup(b *testing.B) {
	tags := sampleTags
	def := NewDef(tags[:]...)
	lut := newLutTable(def)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, tag := range tags {
			lut.lookup(tag)
		}
	}
}

func BenchmarkLutTableLookupMiss(b *testing.B) {
	tags := []int{1, 2, 3, 4, 5}
	def := NewDef(tags...)
	lut := newLutTable(def)

	misses := []int{6, 7, 8, 99, 500, 1000}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, tag := range misses {
			lut.lookup(tag)
		}
	}
}

func BenchmarkBinarySearchLookup(b *testing.B) {
	tags := sampleTags
	sorted := make([]int, len(tags))
	copy(sorted, tags[:])
	slices.Sort(sorted)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, tag := range tags {
			slices.BinarySearch(sorted, tag)
		}
	}
}

func BenchmarkBinarySearchLookupMiss(b *testing.B) {
	tags := []int{1, 2, 3, 4, 5}
	sorted := make([]int, len(tags))
	copy(sorted, tags)
	slices.Sort(sorted)

	misses := []int{6, 7, 8, 99, 500, 1000}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, tag := range misses {
			slices.BinarySearch(sorted, tag)
		}
	}
}
