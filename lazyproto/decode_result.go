package lazyproto

import (
	"fmt"
	"slices"
	"sync"

	"github.com/CrowdStrike/csproto"
)

// DecodeResult holds a (possibly nested) mapping of integer field tags to FieldData instances
// which can be used to retrieve typed values for specific Protobuf message fields.
type DecodeResult struct {
	pool   *sync.Pool
	filter func(int) int

	// flatTags and flatData are equal length, binary searches are used as an optimization
	// but this is essentially equal to a map[int]*FieldData but ranging over a slice is faster than a map.
	flatTags []int
	flatData []*FieldData

	// like flatTags/flatData, nestedTags/nestedData uses binary searching to treat this as
	// a map[int]*Decoder but ranging over a slice is faster than a map.
	nestedTags     []int
	nestedDecoders []*Decoder

	// closers is used to return any nested DecodeResults to their respective pool
	// calling (DecodeResult).Close on a nested DecodeResult has no effect
	closers []*DecodeResult

	maxBuffer int
	skipClose bool
	unsafe    bool
}

// decode parses the data and adds it to the DecodeResult
func (r *DecodeResult) decode(data []byte) error {
	dec := csproto.NewDecoder(data)
	dec.SetMode(csproto.DecoderModeFast)
	for dec.More() {
		tag, wt, err := dec.DecodeTag()
		if err != nil {
			return err
		}

		flatIdx, hasFlat := slices.BinarySearch(r.flatTags, tag)
		if !hasFlat {
			if _, err := dec.Skip(tag, wt); err != nil {
				return err
			}
			continue
		}
		fd := r.flatData[flatIdx]
		if len(fd.data) > 0 && fd.wt != wt {
			return fmt.Errorf("invalid message data - repeated tag %d w/ different wire types (prev=%v, current=%v)", tag, fd.wt, wt)
		}
		switch wt {
		case csproto.WireTypeVarint, csproto.WireTypeFixed32, csproto.WireTypeFixed64:
			// varint, fixed32, and fixed64 could be multiple Go types so
			// grab the raw bytes and defer interpreting them to the consumer/caller
			// . varint -> int32, int64, uint32, uint64, sint32, sint64, bool, enum
			// . fixed32 -> int32, uint32, float32
			// . fixed64 -> int32, uint64, float64
			val, err := dec.Skip(tag, wt)
			if err != nil {
				return err
			}

			// Skip() returns the entire field contents, both the tag and the value, so we need to skip past the tag
			val = val[csproto.SizeOfTagKey(tag):]
			fd.wt = wt
			fd.data = append(fd.data, val)
		case csproto.WireTypeLengthDelimited:
			val, err := dec.DecodeBytes()
			if err != nil {
				return err
			}

			fd.wt = wt
			fd.data = append(fd.data, val)
		default:
			return fmt.Errorf("read unknown/unsupported protobuf wire type (%v)", wt)
		}
	}

	return nil
}

// clone will create a copy of the DecodeResult with the same tag and decoder information
// but a new fieldData slice
func (r *DecodeResult) clone() *DecodeResult {
	if r == nil {
		return nil
	}
	res := &DecodeResult{
		pool:           r.pool,
		filter:         r.filter,
		flatTags:       r.flatTags,
		flatData:       make([]*FieldData, len(r.flatData)),
		nestedTags:     r.nestedTags,
		nestedDecoders: r.nestedDecoders,
		maxBuffer:      r.maxBuffer,
		unsafe:         r.unsafe,
	}
	for i := range r.flatData {
		res.flatData[i] = &FieldData{
			unsafe: r.unsafe,
		}
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
	if r == nil || r.skipClose {
		return nil
	}
	r.close()
	return nil
}

// close will recursively close the nested DecodeResults and return them to their respective pools
func (r *DecodeResult) close() {
	for i := range r.flatData {
		if r.flatData[i] == nil {
			continue
		}
		r.flatData[i].data = r.flatData[i].data[:0]
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
		r.pool.Put(r)
	}
}

// trunc will reallocate slices that have a capacity greater than n
func (r *DecodeResult) trunc(n int) {
	if r == nil || n < 0 {
		return
	}
	if cap(r.closers) > n {
		r.closers = make([]*DecodeResult, n)
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
	if r == nil || (len(r.flatTags) == 0 && len(r.nestedTags) == 0) {
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
	if r == nil || len(r.nestedTags) == 0 {
		return nil, ErrTagNotDefined
	}
	if tag < 0 {
		tag *= -1
	}
	flatIdx, hasFlat := slices.BinarySearch(r.flatTags, tag)
	if !hasFlat {
		return nil, ErrTagNotDefined
	}
	nestedIdx, hasNested := slices.BinarySearch(r.nestedTags, tag)
	if !hasNested {
		return nil, ErrNestingNotDefined
	}

	// get the raw []byte slice for this tag
	b, err := scalarValue(r.flatData[flatIdx], csproto.WireTypeLengthDelimited, func(b []byte) ([]byte, error) {
		return b, nil
	})
	if err != nil {
		return nil, err
	}
	tmp, err := r.nestedDecoders[nestedIdx].decodeWithPool(b)
	if err != nil {
		return nil, err
	}
	tmp.skipClose = true
	r.closers = append(r.closers, tmp)
	return tmp, nil
}

// NestedResults will return all of the DecodeResult located at the give tag path
//
// The tag parameter acts as a "path" to a particular field to support retrieving DecodeResult
// from nested messages.  The value is used to retreieve the field data at the corresponding protonumber
func (r *DecodeResult) NestedResults(tag int) ([]*DecodeResult, error) {
	if r == nil || len(r.nestedTags) == 0 {
		return nil, ErrTagNotDefined
	}
	if tag < 0 {
		tag *= -1
	}
	nestedIdx, hasNested := slices.BinarySearch(r.nestedTags, tag)
	if !hasNested {
		return nil, ErrTagNotDefined
	}
	flatIdx, hasFlat := slices.BinarySearch(r.flatTags, tag)
	if !hasFlat {
		return nil, ErrTagNotDefined
	}
	fd := r.flatData[flatIdx]
	if fd == nil || len(fd.data) == 0 {
		return nil, ErrTagNotFound
	}
	results := make([]*DecodeResult, 0, len(fd.data))
	dec := r.nestedDecoders[nestedIdx]
	for _, b := range fd.data {
		res, err := dec.decodeWithPool(b)
		if err != nil {
			return nil, err
		}
		res.skipClose = true
		results = append(results, res)
	}
	r.closers = append(r.closers, results...)
	return results, nil
}

// Range will iterate over all tags in the DecodeResult.
//
// If a field was not present in the original message fn will be called with the tag and a nil field.
//
// Currently, Range will iterate in the order of the tags, but this is not guaranteed for future use.
func (r *DecodeResult) Range(fn func(tag int, field *FieldData) bool) {
	for idx, tag := range r.flatTags {
		field := r.flatData[idx]
		if field == nil || len(field.data) == 0 {
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
	if r == nil || (len(r.flatTags) == 0) {
		return nil, ErrTagNotDefined
	}
	if tag < 0 {
		tag *= -1
	}

	flatIdx, hasFlat := slices.BinarySearch(r.flatTags, tag)
	if !hasFlat {
		return nil, ErrTagNotDefined
	}

	fd := r.flatData[flatIdx]
	if fd == nil || len(fd.data) == 0 {
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
