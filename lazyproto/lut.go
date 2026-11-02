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

// Bitmap driven lookup table of size 2,984 bytes; designed to fit in the cache.
// An array is used to avoid the indirection and slice bounds checking.
type lutTable struct {
	bitmap   [maxTag/64 + 1]uint64 // Offset 0000: bitmap [297]uint64     2,376 bytes  (8-byte aligned ✓)
	rank     [maxTag/64 + 1]uint16 // Offset 2376: rank   [297]uint16       594 bytes  (2-byte aligned ✓) + 6 bytes padding
	overflow map[int]int           // Offset 2976: overflow map[int]int       8 bytes  (pointer, 8-byte aligned ✓)
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

// Safely lookup tag in lut handing negative tags.
func (t *lutTable) safeLookup(tag int) (int, bool) {
	return t.lookup(absSaturating(tag))
}

// Lookup tag in lut, returns false if not found.
// WARNING: tag must be >= 0 lookup will panic; if unsure use safeLookup.
func (t *lutTable) lookup(tag int) (int, bool) {
	if tag > maxTag {
		slot, ok := t.overflow[tag]
		return slot, ok
	}

	var (
		wordIndex = tag >> 6
		bit       = tag & 63
		mask      = uint64(1) << bit
		word      = t.bitmap[wordIndex]
	)

	if word&mask == 0 {
		return 0, false
	}

	slot := int(t.rank[wordIndex]) + bits.OnesCount64(word&(mask-1))
	return slot, true
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
