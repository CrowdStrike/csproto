package lazyproto

import (
	"iter"
	"math"
	"math/bits"
	"slices"
)

// Limited to max(uint16); aligns with low range of user allowed protobuf field numbers.
// See https://protobuf.dev/programming-guides/proto3/
const maxTag = 19000

// Compile-time assertion: maxTag+1 (maximum possible popcount sum) must fit in uint16, size of rank.
const _ = uint16(maxTag + 1)

// smallTags is the size of lutTable.small, the direct slot table for low
// field numbers. Tags below it are looked up with a single load instead of
// bitmap + rank + popcount; 256 entries (512 bytes) covers field numbers
// that encode in 1 or 2 key bytes up to 255.
const smallTags = 256

// Bitmap driven lookup table of 3,496 bytes; designed to fit in the cache.
// An array is used to avoid the indirection and slice bounds checking.
type lutTable struct {
	bitmap   [maxTag/64 + 1]uint64 // Offset 0000: bitmap [297]uint64     2,376 bytes  (8-byte aligned ✓)
	rank     [maxTag/64 + 1]uint16 // Offset 2376: rank   [297]uint16       594 bytes  (2-byte aligned ✓)
	small    [smallTags]uint16     // Offset 2970: small  [256]uint16       512 bytes  (2-byte aligned ✓) + 6 bytes padding
	overflow map[int]int           // Offset 3488: overflow map[int]int       8 bytes  (pointer, 8-byte aligned ✓)
}

// Create and populate lutTable with data from Def parameter.
func newLutTable(def Def) *lutTable {

	var (
		o []int
		t lutTable
	)

	// Populate the bitmaps
	for k := range def {

		// Negative field values are problematic.
		// Previous code used absolute value so doing the same here.
		k = absSaturating(k)

		if k <= maxTag {
			var (
				word = k >> 6
				bit  = k & 63
			)
			t.bitmap[word] |= uint64(1) << bit
		} else {
			// This case should be rare if hit at all.
			o = append(o, k)
		}
	}

	// Calculate the ranks; ranks contain the sum of the previous ranks.
	var count uint16
	for i, word := range t.bitmap {
		t.rank[i] = count
		count += uint16(bits.OnesCount64(word))
	}

	// Fill the direct table for low tags from the bitmap/rank results, so
	// both lookup paths agree by construction. Stored as slot+1 (0 = absent);
	// slot+1 <= maxTag+1 fits in uint16 (see the assertion above). all()
	// yields in tag order and overflow tags are > maxTag, so stop at the
	// first tag past the table.
	for tag, slot := range t.all() {
		if tag >= smallTags {
			break
		}
		t.small[tag] = uint16(slot + 1)
	}

	// If there is overflow, setup the overflow map.
	// Fields > maxTags are unusual; so we fallback to a simple map.
	// Deduplicate after sorting to handle negative/positive collisions
	// (e.g. -20000 and 20000 both map to 20000 after absSaturating).
	if len(o) > 0 {
		slices.Sort(o)
		o = slices.Compact(o)
		intCnt := int(count)
		t.overflow = make(map[int]int, len(o))
		for _, k := range o {
			t.overflow[k] = intCnt
			intCnt += 1
		}
	}

	return &t
}

// Return the count of fields in the lut
func (t *lutTable) count() int {
	last := len(t.bitmap) - 1
	return int(t.rank[last]) + bits.OnesCount64(t.bitmap[last]) + len(t.overflow)
}

// Returns an iterator over all (tag, slot) pairs in tag order.
func (t *lutTable) all() iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		for i, word := range t.bitmap {
			orig := word
			for word != 0 {
				var (
					bit  = bits.TrailingZeros64(word)
					tag  = i*64 + bit
					mask = uint64(1) << bit
					slot = int(t.rank[i]) + bits.OnesCount64(orig&(mask-1))
				)
				if !yield(tag, slot) {
					return
				}
				word &^= mask // clear lowest set bit
			}
		}
		// Sort overflow keys before yielding to guarantee tag order.
		if len(t.overflow) > 0 {
			keys := make([]int, 0, len(t.overflow))
			for tag := range t.overflow {
				keys = append(keys, tag)
			}
			slices.Sort(keys)
			for _, tag := range keys {
				if !yield(tag, t.overflow[tag]) {
					return
				}
			}
		}
	}
}

// Safelookup safely converts negative tags to positive equivalent.
func (t *lutTable) safeLookup(tag int) (int, bool) {
	return t.lookup(absSaturating(tag))
}

// Lookup tag in lut, returns false if not found; can inline.
// tag is always >= 1 when called from the decode loop (validated before call).
//
// lookup does not consult the small table: adding that branch here would
// push lookup past the inlining budget. The decode loop calls lookupSmall
// for tags below smallTags and lookup for the rest.
func (t *lutTable) lookup(tag int) (slot int, ok bool) {
	// Unsigned comparison collapses tag < 0 (wraps to huge uint) and
	// tag > maxTag into a single branch. Negative tags miss the overflow
	// map (zero value, false) — safe because the decode loop rejects
	// tag < 1 before calling lookup.
	if uint(tag) > uint(maxTag) {
		// Most Defs have no tags above maxTag, so overflow is nil. Skip the
		// runtime map-access call in that case; unknown high-numbered fields
		// (e.g. extension ranges) are then just two branches.
		if t.overflow != nil {
			slot, ok = t.overflow[tag]
		}
		return
	}

	var (
		wordIndex = tag >> 6
		mask      = uint64(1) << (tag & 63)
		word      = t.bitmap[wordIndex]
	)

	if word&mask != 0 {
		ok = true
		slot = int(t.rank[wordIndex]) + bits.OnesCount64(word&(mask-1))
	}
	return
}

// lookupSmall looks tag up in the direct table: one load instead of bitmap +
// rank + popcount. The caller must check uint(tag) < smallTags first and use
// lookup otherwise. slot is meaningful only when ok is true. Inlineable.
//
// The range check stays in the caller on purpose. Folding it in (returning a
// third "small" result) gave the same instruction count but measured 3-5%
// slower at 18-64 fields, because the compiler then hoisted work above the
// range branch. With the check in the caller, the inlined code is identical
// to an open-coded lookup, and the compiler drops the index bounds check.
func (t *lutTable) lookupSmall(tag int) (slot int, ok bool) {
	s := int(t.small[tag]) // slot+1; 0 = not tracked
	return s - 1, s != 0
}

func absSaturating(x int) int {
	switch {
	case x >= 0:
		return x
	case x == math.MinInt:
		return math.MaxInt
	default:
		return -x
	}
}
