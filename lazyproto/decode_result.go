package lazyproto

import (
	"fmt"
	"math"
	"sync"

	"github.com/CrowdStrike/csproto"
)

// DecodeResult holds a (possibly nested) mapping of integer field tags to FieldData instances
// which can be used to retrieve typed values for specific Protobuf message fields.
type DecodeResult struct {
	pool   *sync.Pool
	filter func(int) int

	lut            *lutTable
	flatData       []*FieldData
	nestedDecoders []*Decoder

	// sharedBuf points to a single heap-allocated []byte shared by every
	// coldData in this result. It is allocated in clone() (pool path) or
	// in the deprecated top-level Decode() — not in newBaseResult(),
	// which is only a template. decode() sets *sharedBuf = data once;
	// close() nils it once. No per-field loop needed. The pointer is
	// stable across pool recycling and safe under by-value copies
	// (deprecated Decode() path) because both copies share the same
	// heap location. This is also the GC root that keeps the input
	// buffer alive while any dataPtr is in use.
	sharedBuf *[]byte

	// closers is used to return any nested DecodeResults to their respective pool
	// calling (DecodeResult).Close on a nested DecodeResult has no effect
	closers []*DecodeResult

	maxBuffer int
	skipClose bool
}

// decode parses the data and adds it to the DecodeResult
func (r *DecodeResult) decode(data []byte) error {
	// Enforce the protobuf 2 GiB message-size limit. This also satisfies
	// the dataPtr addressing invariant: offset and length are uint32, so
	// any (offset, length) pair within a ≤MaxInt32 buffer fits in uint32
	// without wraparound. Tightening from MaxUint32 to MaxInt32 closes
	// the gap where SkipBytesInline (which omits a per-field length
	// check to stay within the inlining budget) could accept a 3 GiB
	// field in a 3.5 GiB buffer.
	if len(data) > math.MaxInt32 {
		return fmt.Errorf("input buffer too large (%d bytes); maximum supported size is %d", len(data), math.MaxInt32)
	}

	// Propagate the source data to all coldData entries via the shared
	// buffer pointer — one write, no loop. This is also the GC root.
	*r.sharedBuf = data

	dec := csproto.NewDecoder(data)
	dec.SetMode(csproto.DecoderModeFast)

	var off, sz int

	// This is the hot loop; all the functions called in this loop
	// are intentionally inlined to optimize for speed.
	for dec.More() {
		// Decode tag quickly; call is inlined
		tag, wt, err := dec.DecodeTagInline()
		if err != nil {
			return fmt.Errorf("fail tag decode at byte %d: %w", dec.Offset(), err)
		}

		// Tag range not checked in DecodeTagInline() due to inline budget.
		// Unsigned subtraction trick: tag≤0 wraps to a huge uint, and
		// tag > MaxTagValue stays >= MaxTagValue, collapsing two comparisons
		// into a single CMP + branch.
		if uint(tag-1) >= uint(csproto.MaxTagValue) {
			return fmt.Errorf("invalid tag value (%d) before byte %d: %w", tag, dec.Offset(), csproto.ErrInvalidFieldTag)
		}

		// Skip the field regardless of whether we track the tag;
		// acceptance decision made via lut lookup.  All calls are inlined for speed.
		switch wt {
		case csproto.WireTypeLengthDelimited:
			off, sz, err = dec.SkipBytesInline()
		case csproto.WireTypeVarint:
			off, sz, err = dec.SkipVarintInline()
		case csproto.WireTypeFixed32, csproto.WireTypeFixed64:
			off, sz, err = dec.SkipFixedInline(wt)
		default:
			return fmt.Errorf("unsupported protobuf wire type %d for tag %d at byte %d", wt, tag, dec.Offset())
		}

		if err != nil {
			return fmt.Errorf("fail skip (%d, %s) at byte %d: %w", tag, wt, dec.Offset(), err)
		}

		// Lookup up tag; skip if it does not exist in our table.  Call is inlined
		flatIdx, ok := r.lut.lookup(tag)
		if !ok {
			continue
		}

		// Retrieve corresponding fieldData
		fd := r.flatData[flatIdx]

		switch {
		case !fd.root.hasData():
			// First occurrence — inline into root. Both fields are plain
			// integers so this write triggers zero GC write barriers.
			fd.wt = wt
			fd.root.length = uint32(sz)
			fd.root.offset = uint32(off)
		case fd.wt == wt:
			// Repeated field — spill to cold repeated (rare path).
			fd.cold.repeated = append(fd.cold.repeated, dataPtr{
				length: uint32(sz),
				offset: uint32(off),
			})
		default:
			// NOTE: the protobuf spec allows a repeated numeric field to appear
			// as a mix of packed (WireTypeLengthDelimited) and unpacked (e.g.
			// WireTypeVarint) entries in the same message. This decoder rejects
			// that case. In practice no conformant encoder produces mixed
			// encodings, and supporting it here would complicate the hot loop
			// for a scenario that does not occur in real-world traffic.
			return fmt.Errorf("invalid message data - repeated tag %d w/ different wire types (prev=%v, current=%v)", tag, fd.wt, wt)
		}
	}

	return nil
}

// clone creates a copy of the DecodeResult with the same tag and decoder
// information but a new fieldData slice. When allocBuffers is true, typed
// conversion buffers are allocated for each field (used in DecoderModeFast).
func (r *DecodeResult) clone(allocBuffers bool) *DecodeResult {
	if r == nil {
		return nil
	}

	// Allocate FieldData as a contiguous slab (1 heap allocation + 1 pointer
	// slice). Each FieldData is 24 bytes: wt (8) + root dataPtr (8) + cold
	// pointer (8). The decode loop only writes wt and root — both are plain
	// integers, triggering zero GC write barriers.
	//
	// A separate coldData slab holds the buffer base address, repeated entries
	// for repeated fields, and (in unsafe/fast mode) typed conversion buffers.
	// The cold pointer is set once here and never changes.
	//
	// The flatData pointer slice points into the slab, giving each entry a
	// stable address that survives pool recycling and can be safely handed
	// to external callers via GetFieldData/Range.

	var (
		n         = len(r.flatData)
		slab      = make([]FieldData, n)
		ptrs      = make([]*FieldData, n)
		coldSlab  = make([]coldData, n)
		sharedBuf = new([]byte) // single heap location shared by all coldData
	)

	for i := range slab {
		coldSlab[i].bufPtr = sharedBuf
		slab[i].cold = &coldSlab[i]
		ptrs[i] = &slab[i]
	}

	if allocBuffers {
		bufSlab := make([]fieldDataBuffers, n)
		for i := range coldSlab {
			coldSlab[i].buffers = &bufSlab[i]
		}
	}

	res := &DecodeResult{
		pool:           r.pool,
		filter:         r.filter,
		lut:            r.lut,
		flatData:       ptrs,
		nestedDecoders: r.nestedDecoders,
		maxBuffer:      r.maxBuffer,
		sharedBuf:      sharedBuf,
	}

	return res
}

// Close releases all internal resources held by r.
//
// Consumers should always call Close() on instances returned by [Decode] to ensure that internal
// resources are cleaned up.
//
// When using with csproto.DecoderModeFast it is important that any strings, bytes, etc that were generated
// using any of the DecodeResult/FieldData methods have moved out of scope before closing the DecodeResult.
func (r *DecodeResult) Close() error {
	// skipClose is set on nested DecodeResults that are owned by a parent. When a
	// parent decodes nested messages (via NestedResult / NestedResults), the child
	// results have skipClose=true so that a caller's Close on the child is a no-op;
	// the parent's close() recursively closes all children and returns them to the
	// pool. skipClose is cleared just before a result is returned to the pool so it
	// is ready for reuse.
	if r == nil || r.skipClose {
		return nil
	}
	r.close()
	return nil
}

// close will recursively close the nested DecodeResults and return them to their respective pools
func (r *DecodeResult) close() {
	if r.sharedBuf != nil {
		*r.sharedBuf = nil // release buffer reference for all coldData entries — one write
	}

	for _, fd := range r.flatData {
		if fd == nil {
			continue
		}

		fd.wt = -1          // sentinel: no active wire type — not a valid WireType value
		fd.root = dataPtr{} // zero value: offset=0 means absent — no barrier
		if fd.cold != nil {
			if len(fd.cold.repeated) > 0 {
				fd.cold.repeated = fd.cold.repeated[:0]
			}
		}
	}

	if r.closers != nil {
		for i := range r.closers {
			r.closers[i].close()
		}
		r.closers = r.closers[:0]
	}

	if r.pool != nil {
		if r.maxBuffer >= 0 {
			r.trunc(r.maxBuffer)
		}
		if r.filter != nil {
			if n := r.filter(r.cap()); n >= 0 {
				r.trunc(n)
			}
		}
		r.skipClose = false
		r.pool.Put(r)
	}
}

// trunc will reallocate slices that have a capacity greater than n
func (r *DecodeResult) trunc(n int) {
	if r == nil || n < 0 {
		return
	}
	if cap(r.closers) > n {
		r.closers = make([]*DecodeResult, 0, n)
	}
	for i := range r.flatData {
		r.flatData[i].trunc(n)
	}
}

// cap will return the largest capacity of any slice in the DecodeResult
func (r *DecodeResult) cap() int {
	if r == nil {
		return 0
	}
	c := cap(r.closers)
	for i := range r.flatData {
		if cc := r.flatData[i].cap(); cc > c {
			c = cc
		}
	}
	return c
}

// FieldData returns a FieldData instance for the specified tag "path", if it exists.
//
// The tags parameter is a list of one or more integer field tags that act as a "path" to a particular
// field to support retreiving fields from nested messages.  Each value is used to retreieve the field
// data at the corresponding level of nesting, i.e. a value of [1, 2] would return the field data for
// tag 2 within the nested data for tag 1 at the root.
func (r *DecodeResult) FieldData(tags ...int) (*FieldData, error) {
	if r == nil || r.lut == nil {
		return nil, ErrTagNotDefined
	}
	switch n := len(tags); n {
	case 0:
		return nil, fmt.Errorf("at least one tag key must be specified")
	case 1:
		return r.GetFieldData(tags[0])
	default:
		var err error
		for i := range tags[:n-1] {
			r, err = r.NestedResult(tags[i])
			if err != nil {
				return nil, err
			}
		}
		return r.GetFieldData(tags[n-1])
	}
}

// NestedResult will return the last/only DecodeResult located at the give tag path
//
// The tag parameter acts as a "path" to a particular field to support retrieving DecodeResult
// from nested messages.  The value is used to retreieve the field data at the corresponding protonumber
func (r *DecodeResult) NestedResult(tag int) (*DecodeResult, error) {
	if r == nil || r.lut == nil {
		return nil, ErrTagNotDefined
	}

	flatIdx, hasFlat := r.lut.safeLookup(tag)
	if !hasFlat {
		return nil, ErrTagNotDefined
	}

	nestedDecoder := r.nestedDecoders[flatIdx]
	if nestedDecoder == nil {
		return nil, ErrNestingNotDefined
	}

	// get the raw []byte slice for this tag
	b, err := scalarValue(r.flatData[flatIdx], csproto.WireTypeLengthDelimited, func(b []byte) ([]byte, error) {
		return b, nil
	})
	if err != nil {
		return nil, err
	}
	tmp, err := nestedDecoder.decodeWithPool(b)
	if err != nil {
		return nil, err
	}
	// If the slice is empty, tmp and err are both nil.
	if tmp != nil {
		tmp.skipClose = true
		r.closers = append(r.closers, tmp)
	}
	return tmp, nil
}

// NestedResults will return all of the DecodeResult located at the give tag path
//
// The tag parameter acts as a "path" to a particular field to support retrieving DecodeResult
// from nested messages.  The value is used to retreieve the field data at the corresponding protonumber
func (r *DecodeResult) NestedResults(tag int) ([]*DecodeResult, error) {
	if r == nil || r.lut == nil {
		return nil, ErrTagNotDefined
	}

	flatIdx, hasFlat := r.lut.safeLookup(tag)
	if !hasFlat {
		return nil, ErrTagNotDefined
	}

	nestedDecoder := r.nestedDecoders[flatIdx]
	if nestedDecoder == nil {
		return nil, ErrNestingNotDefined
	}

	fd := r.flatData[flatIdx]
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}

	n := fd.entryCount()

	// results is returned to the caller and may contain nil entries
	// for zero-length nested messages (decodeWithPool returns nil, nil).
	results := make([]*DecodeResult, 0, n)

	// Track where r.closers starts so we can roll back on error
	// instead of allocating a temporary closers slice.
	closerStart := len(r.closers)

	// Cache the buffer base once — avoids repeated calls to
	// fd.cold.baseBuf() per repeated entry below.
	base := fd.cold.baseBuf()

	appendEntry := func(ref dataPtr) error {
		b := ref.bytes(base)
		res, err := nestedDecoder.decodeWithPool(b)
		if err != nil {
			return err
		}

		// (nil,nil) is a valid return for zero-length nested messages.
		// If not nil, mark skipClose and append directly to r.closers.
		if res != nil {
			res.skipClose = true
			r.closers = append(r.closers, res)
		}

		// Append 'res' to results whether or not is nil.
		results = append(results, res)
		return nil
	}

	// Process root
	if err := appendEntry(fd.root); err != nil {
		return nil, err
	}

	// Process repeated entries (repeated nested messages)
	for _, ref := range fd.cold.repeated {
		if err := appendEntry(ref); err != nil {
			// Close already-decoded results and return them to the pool,
			// then roll back r.closers to where we started.
			for _, c := range r.closers[closerStart:] {
				c.close()
			}
			r.closers = r.closers[:closerStart]
			return nil, err
		}
	}

	return results, nil
}

// Range will iterate over all tags in the DecodeResult.
//
// If a field was not present in the original message fn will be called with the tag and a nil field.
//
// Currently, Range will iterate in the order of the tags, but this is not guaranteed for future use.
func (r *DecodeResult) Range(fn func(tag int, field *FieldData) bool) {
	if r == nil || r.lut == nil {
		return
	}

	for tag, slot := range r.lut.all() {
		field := r.flatData[slot]
		if !field.hasData() {
			if !fn(tag, nil) {
				return
			}
			continue
		}
		if !fn(tag, field) {
			return
		}
	}
}

// GetFieldData returns the raw field data object at the given tag
func (r *DecodeResult) GetFieldData(tag int) (*FieldData, error) {
	if r == nil || r.lut == nil {
		return nil, ErrTagNotDefined
	}

	flatIdx, hasFlat := r.lut.safeLookup(tag)
	if !hasFlat {
		return nil, ErrTagNotDefined
	}

	fd := r.flatData[flatIdx]
	if !fd.hasData() {
		return nil, ErrTagNotFound
	}
	return fd, nil
}

// loadFieldDataType will use the provided function to load the field data at the given tag and cast it to the desired type.
func loadFieldDataType[T any](r *DecodeResult, tag int, fn func(*FieldData) (T, error)) (T, error) {
	fd, err := r.GetFieldData(tag)
	if err != nil {
		var zero T
		return zero, err
	}
	return fn(fd)
}

// BoolValue is a helper method to get the field data at the given tag and return it as a boolean.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.BoolValue()
func (r *DecodeResult) BoolValue(tag int) (bool, error) {
	return loadFieldDataType(r, tag, (*FieldData).BoolValue)
}

// BoolValues is a helper method to get the field data at the given tag and return it as a boolean slice.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.BoolValues()
func (r *DecodeResult) BoolValues(tag int) ([]bool, error) {
	return loadFieldDataType(r, tag, (*FieldData).BoolValues)
}

// BytesValue is a helper method to get the field data at the given tag and return it as a byte slice.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.BytesValue()
func (r *DecodeResult) BytesValue(tag int) ([]byte, error) {
	return loadFieldDataType(r, tag, (*FieldData).BytesValue)
}

// BytesValues is a helper method to get the field data at the given tag and return it as a []byte slice.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.BytesValues()
func (r *DecodeResult) BytesValues(tag int) ([][]byte, error) {
	return loadFieldDataType(r, tag, (*FieldData).BytesValues)
}

// Fixed32Value is a helper method to get the field data at the given tag and return it as a uint32.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Fixed32Value()
func (r *DecodeResult) Fixed32Value(tag int) (uint32, error) {
	return loadFieldDataType(r, tag, (*FieldData).Fixed32Value)
}

// Fixed32Values is a helper method to get the field data at the given tag and return it as a []uint32.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Fixed32Values()
func (r *DecodeResult) Fixed32Values(tag int) ([]uint32, error) {
	return loadFieldDataType(r, tag, (*FieldData).Fixed32Values)
}

// Fixed64Value is a helper method to get the field data at the given tag and return it as a uint64.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Fixed64Value()
func (r *DecodeResult) Fixed64Value(tag int) (uint64, error) {
	return loadFieldDataType(r, tag, (*FieldData).Fixed64Value)
}

// Fixed64Values is a helper method to get the field data at the given tag and return it as a []uint64.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Fixed64Values()
func (r *DecodeResult) Fixed64Values(tag int) ([]uint64, error) {
	return loadFieldDataType(r, tag, (*FieldData).Fixed64Values)
}

// Float32Value is a helper method to get the field data at the given tag and return it as a float32.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Float32Value()
func (r *DecodeResult) Float32Value(tag int) (float32, error) {
	return loadFieldDataType(r, tag, (*FieldData).Float32Value)
}

// Float32Values is a helper method to get the field data at the given tag and return it as a []float32.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Float32Values()
func (r *DecodeResult) Float32Values(tag int) ([]float32, error) {
	return loadFieldDataType(r, tag, (*FieldData).Float32Values)
}

// Float64Value is a helper method to get the field data at the given tag and return it as a float64.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Float64Value()
func (r *DecodeResult) Float64Value(tag int) (float64, error) {
	return loadFieldDataType(r, tag, (*FieldData).Float64Value)
}

// Float64Values is a helper method to get the field data at the given tag and return it as a []float64.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Float64Values()
func (r *DecodeResult) Float64Values(tag int) ([]float64, error) {
	return loadFieldDataType(r, tag, (*FieldData).Float64Values)
}

// Int32Value is a helper method to get the field data at the given tag and return it as an int32.
//
// Use this method to retrieve values that are defined as int32 in the Protobuf message. Fields that
// are defined as sint32 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt32Value() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Int32Value()
func (r *DecodeResult) Int32Value(tag int) (int32, error) {
	return loadFieldDataType(r, tag, (*FieldData).Int32Value)
}

// Int32Values is a helper method to get the field data at the given tag and return it as a []int32.
//
// Use this method to retrieve values that are defined as repeated int32 in the Protobuf message. Fields that
// are defined as repeated sint32 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt32Values() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Int32Values()
func (r *DecodeResult) Int32Values(tag int) ([]int32, error) {
	return loadFieldDataType(r, tag, (*FieldData).Int32Values)
}

// Int64Value is a helper method to get the field data at the given tag and return it as an int64.
//
// Use this method to retrieve values that are defined as int64 in the Protobuf message. Fields that
// are defined as sint64 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt64Value() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Int64Value()
func (r *DecodeResult) Int64Value(tag int) (int64, error) {
	return loadFieldDataType(r, tag, (*FieldData).Int64Value)
}

// Int64Values is a helper method to get the field data at the given tag and return it as a []int64.
//
// Use this method to retrieve values that are defined as repeated int64 in the Protobuf message. Fields that
// are defined as repeated sint64 (and so use the [Protobuf ZigZag encoding]) should be retrieved using
// SInt64Values() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.Int64Values()
func (r *DecodeResult) Int64Values(tag int) ([]int64, error) {
	return loadFieldDataType(r, tag, (*FieldData).Int64Values)
}

// SInt32Value is a helper method to get the field data at the given tag and return it as an int32.
//
// Use this method to retrieve values that are defined as sint32 in the Protobuf message. Fields that
// are defined as int32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Value() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.SInt32Value()
func (r *DecodeResult) SInt32Value(tag int) (int32, error) {
	return loadFieldDataType(r, tag, (*FieldData).SInt32Value)
}

// SInt32Values is a helper method to get the field data at the given tag and return it as a []int32.
//
// Use this method to retrieve values that are defined as repeated sint32 in the Protobuf message. Fields that
// are defined as repeated int32 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int32Values() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.SInt32Values()
func (r *DecodeResult) SInt32Values(tag int) ([]int32, error) {
	return loadFieldDataType(r, tag, (*FieldData).SInt32Values)
}

// SInt64Value is a helper method to get the field data at the given tag and return it as an int64.
//
// Use this method to retrieve values that are defined as sint64 in the Protobuf message. Fields that
// are defined as int64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Value() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.SInt32Value()
func (r *DecodeResult) SInt64Value(tag int) (int64, error) {
	return loadFieldDataType(r, tag, (*FieldData).SInt64Value)
}

// SInt64Values is a helper method to get the field data at the given tag and return it as a []int64.
//
// Use this method to retrieve values that are defined as repeated sint64 in the Protobuf message. Fields that
// are defined as repeated int64 (and so use the [Protobuf base128 varint encoding]) should be retrieved using
// Int64Values() instead.
//
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.SInt64Values()
func (r *DecodeResult) SInt64Values(tag int) ([]int64, error) {
	return loadFieldDataType(r, tag, (*FieldData).SInt64Values)
}

// StringValue is a helper method to get the field data at the given tag and return it as a string.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.StringValue()
func (r *DecodeResult) StringValue(tag int) (string, error) {
	return loadFieldDataType(r, tag, (*FieldData).StringValue)
}

// StringValues is a helper method to get the field data at the given tag and return it as a []string.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.StringValues()
func (r *DecodeResult) StringValues(tag int) ([]string, error) {
	return loadFieldDataType(r, tag, (*FieldData).StringValues)
}

// UInt32Value is a helper method to get the field data at the given tag and return it as a uint32.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.UInt32Value()
func (r *DecodeResult) UInt32Value(tag int) (uint32, error) {
	return loadFieldDataType(r, tag, (*FieldData).UInt32Value)
}

// UInt32Values is a helper method to get the field data at the given tag and return it as a []uint32.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.UInt32Values()
func (r *DecodeResult) UInt32Values(tag int) ([]uint32, error) {
	return loadFieldDataType(r, tag, (*FieldData).UInt32Values)
}

// UInt64Value is a helper method to get the field data at the given tag and return it as a uint64.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.UInt64Value()
func (r *DecodeResult) UInt64Value(tag int) (uint64, error) {
	return loadFieldDataType(r, tag, (*FieldData).UInt64Value)
}

// UInt64Values is a helper method to get the field data at the given tag and return it as a []uint64.
// It is equivalent to
//
//	fd, err := r.GetFieldData(tag)
//	if err != nil {
//	  return err
//	}
//	v, err := fd.UInt64Values()
func (r *DecodeResult) UInt64Values(tag int) ([]uint64, error) {
	return loadFieldDataType(r, tag, (*FieldData).UInt64Values)
}
