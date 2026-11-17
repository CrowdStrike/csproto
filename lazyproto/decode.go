package lazyproto

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/internal/wire"
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
	// ErrUnsupportedWireType is returned (wrapped) by Decode when the message contains a field
	// encoded with a wire type lazyproto does not support: the deprecated group wire types
	// (start group = 3, end group = 4) or the undefined values 6 and 7.
	ErrUnsupportedWireType = errors.New("unsupported protobuf wire type")
	// ErrMixedWireTypes is returned (wrapped) by Decode when a field defined in the decoder appears
	// more than once with different wire types, e.g. a repeated numeric field encoded both packed
	// (length-delimited) and unpacked in the same message. The protobuf spec allows mixing packed
	// and unpacked entries, but lazyproto does not support it.
	ErrMixedWireTypes = errors.New("repeated tag with different wire types")
)

var emptyResult DecodeResult

// errInvalidDecoder is returned by [Decoder.Decode] when the Decoder was not built by [NewDecoder].
var errInvalidDecoder = errors.New("invalid decoder")

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
// data must not exceed math.MaxInt32 bytes (the 2 GiB protobuf message-size limit), and field
// keys with field number 0 are rejected with [csproto.ErrInvalidFieldTag]; see [Decoder.Decode]
// for details and the compatibility notes.
//
// Deprecated: use NewDecoder(def) and (*Decoder).Decode(data)
// For best performance, decoders should be initialized once per definition and reused when decoding data
func Decode(data []byte, def Def) (DecodeResult, error) {
	if len(data) == 0 || len(def) == 0 {
		return emptyResult, nil
	}
	// Check the size (and copy) before building the decoder tree and slabs,
	// so oversized input fails fast with nothing allocated beyond the check.
	data, err := cloneInput(data)
	if err != nil {
		return emptyResult, err
	}
	// Not pooled, so slices are never truncated: no WithMaxBufferSize limit.
	// maxBuffer must be -1 (not 0) so nested decoders inherit "unlimited" too.
	dec := &Decoder{maxBuffer: -1}
	base, err := dec.newBaseResult(def)
	if err != nil || base == nil {
		return emptyResult, err
	}
	// Same slab setup as pooled results; dec has no pool, so the result is
	// never returned to one.
	result := base.clone(false)
	if err = result.decode(data); err != nil {
		return emptyResult, err
	}
	return *result, nil
}

// cloneInput copies data for safe-mode decoding. It rejects buffers over the
// 2 GiB protobuf limit before copying, so an oversized input fails fast
// instead of being copied in full only to be rejected by wire.NewCursor.
func cloneInput(data []byte) ([]byte, error) {
	if err := wire.CheckLen(len(data)); err != nil {
		return nil, bufferTooLargeErr(len(data), err)
	}
	return slices.Clone(data), nil
}

// bufferTooLargeErr wraps wire.ErrBufferTooLarge with the input size.
func bufferTooLargeErr(n int, err error) error {
	return fmt.Errorf("input buffer too large (%d bytes): %w", n, err)
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
// - DecoderModeSafe will create copies of the input data slice and create new slices for any returned field data results.
// This does not make a [DecodeResult] safe for concurrent use: in every mode, use a separate DecodeResult per goroutine
// or synchronize access.
//
// - DecoderModeFast will not reallocate input data or slices. When the mode is DecoderModeFast it is not safe to modify the
// input data slice after calling (*Decoder).Decode(data) and it is not safe to use any slices after calling (*DecodeResult).Close().
// In addition, the slice returned by a FieldData XxxValues method (for example StringValues or BytesValues) is a per-field
// buffer that is reused by later XxxValues calls on the same field; copy it if it must outlive the next call.
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
	alloc := dec.mode != csproto.DecoderModeSafe
	dec.pool.New = func() any {
		return base.clone(alloc)
	}
	return dec, nil
}

// Decode will convert the raw []byte slice to a DecodeResult
//
// data must not exceed math.MaxInt32 bytes (the 2 GiB protobuf message-size limit) in any
// [csproto.DecoderMode]; larger inputs are rejected up front with an error that wraps
// [csproto.ErrLenOverflow]. In [csproto.DecoderModeSafe] the check runs before data is copied.
//
// A field key whose field number is 0 is rejected with an error that wraps
// [csproto.ErrInvalidFieldTag], whatever its wire type; 0 is never a valid Protobuf field number.
//
// Compatibility notes:
//   - Earlier versions only rejected individual length-delimited fields larger than 2 GiB, so an
//     oversized buffer whose fields were each under the limit (e.g. several concatenated
//     messages) used to decode. Such inputs now fail; split them before decoding.
//   - Earlier versions accepted keys 0x01-0x07 (field number 0 with a non-zero wire type) as tag
//     0 and silently skipped them, so e.g. {0x02, 0x00, 0x08, 0x01} (an empty length-delimited
//     field 0 followed by field 1 = 1) decoded with field 1 readable. Such inputs now fail with
//     [csproto.ErrInvalidFieldTag], matching [csproto.Decoder.DecodeTag]. Key 0x00 was already
//     rejected.
func (dec *Decoder) Decode(data []byte) (*DecodeResult, error) {
	if dec.pool == nil {
		// Only a Decoder not built by NewDecoder (e.g. a zero value) has no pool.
		// Checked before cloneInput so an invalid decoder never copies data.
		return nil, errInvalidDecoder
	}
	if dec.mode == csproto.DecoderModeSafe {
		var err error
		if data, err = cloneInput(data); err != nil {
			return nil, err
		}
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
		return nil, errInvalidDecoder
	}
	err := res.decode(data)
	if err != nil {
		// call res.close() on error to clean up field data
		res.close()
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

	maxBuffer := dec.maxBuffer
	if maxBuffer < 0 {
		maxBuffer = math.MaxInt // no WithMaxBufferSize limit
	}
	result := &DecodeResult{
		lut:    newLutTable(def),
		pool:   dec.pool,
		filter: dec.filter,
		// The template never decodes, so its sharedState carries only the
		// limit; clone() copies it into each result's own sharedState.
		shared: &sharedState{maxBuffer: maxBuffer},
	}

	// The template has no FieldData slab; clone() allocates one per result,
	// sized from lut.count().
	slotCnt := result.lut.count()

	// create decoders for any nested results
	result.nestedDecoders = make([]*Decoder, slotCnt)

	for k, v := range def {
		if v == nil {
			continue
		}

		slot, ok := result.lut.safeLookup(k)
		if !ok || slot < 0 || slot >= slotCnt {
			return nil, errors.New("unexpected lut fail initializing nested decoders")
		}

		nestedDec, err := NewDecoder(v, func(d *Decoder) error {
			d.filter = dec.filter
			d.maxBuffer = dec.maxBuffer
			d.mode = dec.mode
			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("invalid definition on tag: %d", k)
		}
		result.nestedDecoders[slot] = nestedDec
	}

	return result, nil
}
