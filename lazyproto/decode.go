package lazyproto

import (
	"fmt"
	"slices"
	"sync"

	"github.com/CrowdStrike/csproto"
)

var (
	// ErrNestingNotDefined is returned by [PartialDecodeResult.FieldData] when the specified tag
	// was not supplied with a nested definitions. This will also return true for errors.Is(err, ErrTagNotFound) but is
	// more specific because this means the tag nesting was not in the original decoder definition
	ErrNestingNotDefined = fmt.Errorf("%w: the requested tag was not defined as a nested tag in the decoder", ErrTagNotFound)
	// ErrTagNotDefined is returned by [PartialDecodeResult.FieldData] when the specified tag
	// was not defined in the decoder. This will also return true for errors.Is(err, ErrTagNotFound) but is
	// more specific because this means the tag was not in the original decoder definition
	ErrTagNotDefined = fmt.Errorf("%w: the requested tag was not defined in the decoder", ErrTagNotFound)
	// ErrTagNotFound is returned by [PartialDecodeResult.FieldData] when the specified tag(s) do not
	// exist in the result.
	ErrTagNotFound = fmt.Errorf("the requested tag does not exist in the partial decode result")
)

var emptyResult DecodeResult

// Decode extracts the specified field tags from data without unmarshaling the entire message.
// The methods on the returned PartialDecodeResult can be used to retrieve the decoded values.
//
// The def param is an optionally nested mapping of protobuf field tags declaring which values should
// be decoded from the message.  If the value for a given tag is a nested mapping and the wire type
// in the encoded data is WireTypeLengthDelimited , the contents are treated as a nested message and is
// decoded recursively.
//
// The purpose of this API is to avoid fully unmarshalling nested message data when only a small subset
// of field values are needed, so [PartialDecodeResult] and [FieldData] only support extracting
// scalar values or slices of scalar values. Consumers that need to decode entire messages will need
// to use [Unmarshal] instead.
//
// Deprecated: use NewDecoder(def) and (*Decoder).Decode(data)
// For best performance, decoders should be initialized once per definition and reused when decoding data
func Decode(data []byte, def Def) (DecodeResult, error) {
	if len(data) == 0 || len(def) == 0 {
		return emptyResult, nil
	}
	dec := &Decoder{}
	result, err := dec.newBaseResult(def)
	if err != nil || result == nil {
		return emptyResult, err
	}
	for i := range result.flatData {
		result.flatData[i] = new(FieldData)
	}
	err = result.decode(slices.Clone(data))
	if err != nil {
		return emptyResult, err
	}
	return *result, nil
}

// Option is a functional option that allows configuring new Decoders
type Option func(*Decoder) error

// WithMaxBufferSize will prevent slices greater than n from being cached for future reuse
func WithMaxBufferSize(n int) Option {
	return func(d *Decoder) error {
		if n < 0 {
			return fmt.Errorf("WithMaxBuffer: negative max buffer size is not allowed")
		}
		d.maxBuffer = n
		return nil
	}
}

// WithBufferFilterFunc can prevent slices from being cached for future reuse.
//
// Under the hood, decoders will use sync Pools to avoid allocations for slices.
// If messages intermitently contain very large slices it can cause all of the cached
// decode results to eventually use the max slice value.
// This may result in larger memory use than is necessary. To avoid such a scenario,
// clients may set a BufferFilterFunction to cleanup slices based on their capacity.
//
// fn accepts the current slice capacity and should return the target capacity.
// Negative capacities will be ignored.
func WithBufferFilterFunc(fn func(capacity int) int) Option {
	return func(d *Decoder) error {
		if fn == nil {
			return fmt.Errorf("WithMaxBufferFunc: nil function is not allowed")
		}
		d.filter = fn
		return nil
	}
}

// WithMode will set the mode of operation for the decoder
//
// - DecoderModeSafe will create copies of the input data slice and create new slices for any returned field data results
//
// - DecoderModeFast will not reallocate input data or slices. When the mode is DecoderModeFast it is not safe to modify the
// input data slice after calling (*Decoder).Decode(data) and it is not safe to use any slices after calling (*DecodeResult).Close()
func WithMode(mode csproto.DecoderMode) Option {
	return func(d *Decoder) error {
		d.mode = mode
		return nil
	}
}

// Decoder is a lazy decoder that will reuse DecodeResults after (DecodeResult).Close()
// is called.
//
// A decoder is unique to a given Definition and can be reused for any protobuf message using
// that definition.
//
// Decoder methods are thread safe and can be used by concurrent/parallel processes.
type Decoder struct {
	pool      *sync.Pool
	filter    func(int) int
	maxBuffer int
	mode      csproto.DecoderMode
}

// NewDecoder creates a new Decoder for a given Def. See NewDef for defining a definition.
//
// NewDecoder will return an error if the definition or options are invalid
func NewDecoder(def Def, opts ...Option) (*Decoder, error) {
	err := def.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid definition: %w", err)
	}

	dec := &Decoder{
		pool:      new(sync.Pool),
		maxBuffer: -1,
		mode:      csproto.DecoderModeSafe,
	}
	for _, opt := range opts {
		err := opt(dec)
		if err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	base, err := dec.newBaseResult(def)
	if err != nil {
		return nil, err
	}
	dec.pool.New = func() any {
		return base.clone()
	}
	return dec, nil
}

// Decode will convert the raw []byte slice to a DecodeResult
func (dec *Decoder) Decode(data []byte) (*DecodeResult, error) {
	if dec.mode == csproto.DecoderModeSafe {
		return dec.decodeWithPool(slices.Clone(data))
	}
	return dec.decodeWithPool(data)
}

func (dec *Decoder) decodeWithPool(data []byte) (*DecodeResult, error) {
	if len(data) == 0 {
		return nil, nil
	}
	res, ok := dec.pool.Get().(*DecodeResult)
	if !ok {
		// This will only happen if the decoder was initialized outside of NewDecoder
		return nil, fmt.Errorf("invalid decoder")
	}
	err := res.decode(data)
	if err != nil {
		// call res.Close() on error to clean up field data
		_ = res.Close()
		return nil, err
	}
	return res, nil
}

// newBaseResult creates a new DecodeResult object based on the given definition
// all other initialization of this DecodeResult is done by cloning the resulting object
func (dec *Decoder) newBaseResult(def Def) (*DecodeResult, error) {
	err := def.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid definition: %w", err)
	}
	result := &DecodeResult{
		pool:      dec.pool,
		filter:    dec.filter,
		maxBuffer: dec.maxBuffer,
		unsafe:    dec.mode != csproto.DecoderModeSafe,
	}

	// iterate over all of the flat/raw tags and any nested tags in the definition
	for k, v := range def {
		if k < 0 {
			k *= -1
		}
		result.flatTags = append(result.flatTags, k)
		if v == nil {
			continue
		}
		result.nestedTags = append(result.nestedTags, k)
	}

	// sort and deduplicate the tags
	slices.Sort(result.flatTags)
	result.flatTags = slices.Compact(result.flatTags)
	slices.Sort(result.nestedTags)
	result.nestedTags = slices.Compact(result.nestedTags)

	// intitialize the slice length
	// (we don't need to fill the slice because that will be done when it's cloned)
	result.flatData = make([]*FieldData, len(result.flatTags))

	// create decoders for any nested results
	result.nestedDecoders = make([]*Decoder, len(result.nestedTags))
	for i, tag := range result.nestedTags {
		nestedDec, err := NewDecoder(def[tag], func(d *Decoder) error {
			d.filter = dec.filter
			d.maxBuffer = dec.maxBuffer
			d.mode = dec.mode
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("invalid definition on tag: %d", tag)
		}
		result.nestedDecoders[i] = nestedDec
	}
	return result, nil
}
