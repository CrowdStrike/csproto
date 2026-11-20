// Package wire provides a minimal, inlineable protobuf wire-format cursor for
// internal hot loops (lazyproto's decode loop).
//
// The methods here have different contracts than their counterparts on
// [csproto.Decoder] so that each one fits within the Go inliner's budget
// (cost ≤ 80):
//
//   - The input buffer must not exceed math.MaxInt32 bytes (the protobuf
//     2 GiB message limit); [NewCursor] rejects larger buffers.
//   - Hot-path methods return internal sentinel errors instead of
//     classifying failures inline; callers must pass every error through
//     [Cursor.RefineErr] to get the public csproto error.
//   - Wire types are not validated by [Cursor.NextTag].
//   - The hot-path methods (NextShortTag, NextTag, Peek*, Seek, More, Offset)
//     take and return the Cursor by value, so a caller's loop never takes
//     the cursor's address and the compiler can keep it in registers.
//
// Keeping them in an internal package prevents these contracts from becoming
// public API.
package wire

import (
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/CrowdStrike/csproto"
)

// ErrBufferTooLarge is returned by [NewCursor] when the buffer exceeds
// math.MaxInt32 bytes. It wraps [csproto.ErrLenOverflow], so oversized
// buffers and oversized fields classify the same way with errors.Is.
var ErrBufferTooLarge = fmt.Errorf("buffer exceeds the 2 GiB protobuf message limit: %w", csproto.ErrLenOverflow)

// Internal sentinels returned by the hot-path methods instead of classifying
// a failure inline (no varint terminator within the scan window, or a decoded
// length that exceeds the remaining buffer). Returning a sentinel is a single
// store, whereas classifying the failure (truncated vs. overflow vs. too wide
// vs. over 2 GiB) needs extra branches that would exceed the inlining budget.
// Callers MUST pass any error from [Cursor.NextTag], [Cursor.PeekBytes] or
// [Cursor.PeekVarint] (or their in-place wrappers) through [Cursor.RefineErr]
// before surfacing it.
var (
	errTag          = errors.New("wire: tag varint not terminated within scan window or out of range")
	errLen          = errors.New("wire: length varint not terminated within scan window or exceeds remaining buffer")
	errVarintWindow = errors.New("wire: varint value not terminated within scan window")
)

// maxVarint is the maximum number of bytes in a varint.
const maxVarint = 10

// capShifts is a lookup table for varint bit-shift amounts with shifts capped
// at 35. Using a table index instead of a multiply (uint(n) * 7) saves 1
// inlining cost unit.
//
// Varints are little-endian base-128, so bytes 0-4 carry bits 0-34 and any
// later bytes carry only higher-order groups. Both users only accept values
// below 2³⁵ — NextTag requires keys < 2³², and PeekBytes requires lengths
// that fit in the buffer (len(c.p) ≤ MaxInt32) — so for an accepted value
// every byte from index 5 onward has zero data bits and v is exact. Any
// non-zero data bit there lands in bits 35-41, forcing v ≥ 2³⁵ and a
// rejection. Capping also guarantees nothing is shifted out of uint64
// (v < 2⁴²), so both methods can scan all 10 bytes — accepting zero-padded
// encodings — without a separate 10th-byte overflow check. Rejected inputs
// are re-decoded with the true shifts by [Cursor.RefineErr].
var capShifts = [maxVarint]uint{0, 7, 14, 21, 28, 35, 35, 35, 35, 35}

// Cursor is a forward-only read position over a protobuf-encoded buffer.
//
// The zero value is an empty cursor. Cursor is small (a slice header plus an
// int) and is intended to live on the stack.
//
// Invariant: len(p) <= math.MaxInt32 (the protobuf 2 GiB message limit).
// The fields are unexported, so outside this package a Cursor can only come
// from [NewCursor] (which enforces the limit) or be the zero value (empty).
// capShifts and PeekBytes rely on this invariant.
type Cursor struct {
	p      []byte
	offset int
}

// CheckLen returns [ErrBufferTooLarge] if a buffer of n bytes exceeds the
// math.MaxInt32 (protobuf 2 GiB) limit enforced by [NewCursor]. Callers that
// copy their input before building a cursor should call it first, so an
// oversized buffer is rejected without allocating a copy of it.
func CheckLen(n int) error {
	if n > math.MaxInt32 {
		return ErrBufferTooLarge
	}
	return nil
}

// NewCursor returns a Cursor positioned at the start of p.
//
// It returns [ErrBufferTooLarge] if len(p) exceeds math.MaxInt32 (the
// protobuf 2 GiB message limit), which [Cursor.PeekBytes] relies on to reject
// corrupted length prefixes. The check runs once per cursor, not per field;
// on 32-bit platforms it is always false and compiled away.
func NewCursor(p []byte) (Cursor, error) {
	if err := CheckLen(len(p)); err != nil {
		return Cursor{}, err
	}
	return Cursor{p: p}, nil
}

// More reports whether there is unread data remaining.
func (c Cursor) More() bool {
	return c.offset < len(c.p)
}

// Offset returns the current read position within the buffer.
func (c Cursor) Offset() int {
	return c.offset
}

// NextTag decodes a field tag and wire type from the current position and
// returns the cursor advanced past the key.
//
// The Next* methods take and return the Cursor by value so that a caller's
// loop (dec, ... = dec.NextTag()) never takes the cursor's address. That
// lets the compiler keep the cursor in registers instead of reloading and
// storing it on every iteration.
//
// This variant is inlineable (cost ≤ 80). It validates that the field number
// is in [1, csproto.MaxTagValue] (per the protobuf spec, matching
// [csproto.Decoder.DecodeTag]) and accepts
// zero-padded keys up to 10 bytes on both 32- and 64-bit. The wire type is
// not validated. The offset is advanced only on success; on error next == c
// and the invariant c.offset <= len(c.p) is preserved.
//
// Error types (after [Cursor.RefineErr]):
//   - [io.ErrUnexpectedEOF]: the buffer ends before the varint terminates.
//   - [csproto.ErrValueOverflow]: 10 or more continuation bytes, or a 10-byte
//     varint whose last byte overflows uint64.
//   - [csproto.ErrInvalidFieldTag]: field number 0 or greater than MaxTagValue.
//
// The raw error returned by this method is an internal sentinel and must be
// passed through [Cursor.RefineErr] on the returned cursor.
//
// Requires 0 <= c.offset <= len(c.p) on entry.
func (c Cursor) NextTag() (next Cursor, tag int, wireType csproto.WireType, err error) {
	var v uint64
	next = c

	// Scan the full 10-byte varint window on every platform. capShifts caps
	// shifts at 35, so v never loses bits and int(v>>3) below is safe on
	// 32-bit (it only runs after the uint64 range check).
	// Compute count first to avoid c.offset+maxVarint overflow on 32-bit.
	for n, b := range c.p[c.offset : c.offset+min(maxVarint, len(c.p)-c.offset)] {
		v |= (uint64(b) & 0x7f) << capShifts[n]
		if b < 0x80 {
			// 1 <= v>>3 <= MaxTagValue  ⇔  8 <= v < (MaxTagValue+1)<<3.
			// Unsigned wrap makes v < 8 (tag 0) huge, so one compare rejects
			// both tag 0 and tags > MaxTagValue.
			if v-8 < csproto.MaxTagValue<<3 {
				tag = int(v >> 3)
				wireType = csproto.WireType(v & 0x7)
				next.offset += n + 1
				return
			}
			break
		}
	}

	// No terminator within the window, or tag out of range. Classification
	// is deferred to RefineErr (cold path) to keep this method inlineable.
	err = errTag
	return
}

// NextShortTag is a loop-free fast path for [Cursor.NextTag] that handles
// 1- and 2-byte keys, i.e. field numbers 1-2047, which cover nearly all
// real messages. On success it returns the advanced cursor and a tag >= 1.
// Otherwise it returns c unchanged and tag == 0 (never a valid field
// number), and the caller must fall back to NextTag, which handles longer
// keys and reports errors (including field number 0, which this method
// never accepts).
//
// Accepts exactly what NextTag accepts for these inputs: a 2-byte key may
// be a zero-padded form of a 1-byte key (e.g. 0x88 0x00 is field 1,
// varint), and every 2-byte value is at most 2047<<3|7, well under
// MaxTagValue.
//
// Inlineable. Requires 0 <= c.offset < len(c.p) on entry (at least one
// unread byte, as [Cursor.More] reports); it panics otherwise.
func (c Cursor) NextShortTag() (next Cursor, tag int, wireType csproto.WireType) {
	next = c
	v, n := uint(c.p[c.offset]), 1
	if v >= 0x80 {
		if len(c.p)-c.offset < 2 || c.p[c.offset+1] >= 0x80 {
			return // longer than 2 bytes, or truncated: let NextTag decide
		}
		v, n = v&0x7f|uint(c.p[c.offset+1])<<7, 2
	}
	// v < 8 is field number 0; leave tag == 0 so NextTag reports it.
	if v >= 8 {
		next.offset += n
		tag, wireType = int(v>>3), csproto.WireType(v&7)
	}
	return
}

// Seek returns c positioned at off. It is the advance step for the Peek*
// methods: after a successful dec.PeekBytes() (or PeekVarint, PeekFixed32,
// PeekFixed64), dec = dec.Seek(off + sz) moves past the field. Taking and
// returning the Cursor by value keeps it in registers; see [Cursor.NextTag].
//
// Requires 0 <= off <= len(c.p), which off+sz from a successful Peek* call
// always satisfies.
func (c Cursor) Seek(off int) Cursor {
	c.offset = off
	return c
}

// PeekBytes locates the length-delimited field value (varint length prefix +
// payload) at the current position and returns the offset and length of the
// payload within the input buffer. It does not advance the cursor: the field
// ends at offset+length, so callers continue with c.Seek(offset+length). No
// slice is allocated — callers index the original buffer with
// data[offset:offset+length].
//
// Inlineable (cost ≤ 80). The length prefix may use the full 10-byte varint
// window, so zero-padded (non-canonical) prefixes are accepted, matching
// [csproto.Decoder.DecodeBytes].
//
// Error types (after [Cursor.RefineErr]):
//   - [io.ErrUnexpectedEOF]: the buffer ends inside the length varint, or the
//     declared payload length (≤ 2 GiB) exceeds the remaining buffer.
//   - [csproto.ErrValueOverflow]: 10 or more continuation bytes, or a 10-byte
//     varint whose last byte overflows uint64.
//   - [csproto.ErrLenOverflow]: the declared length exceeds 2 GiB.
//
// The raw error returned by this method is an internal sentinel and must be
// passed through [Cursor.RefineErr].
//
// Requires 0 <= c.offset <= len(c.p) on entry (len(c.p) <= math.MaxInt32 is a
// Cursor invariant enforced by NewCursor).
func (c Cursor) PeekBytes() (offset int, length int, err error) {
	var v uint64

	// Compute count first to avoid c.offset+maxVarint overflow on 32-bit.
	for n, b := range c.p[c.offset : c.offset+min(maxVarint, len(c.p)-c.offset)] {
		// capShifts keeps v exact for any length that can fit in the buffer
		// and forces v ≥ 2³⁵ (rejected below) otherwise; v < 2⁴² always.
		v |= (uint64(b) & 0x7f) << capShifts[n]
		if b < 0x80 {
			// end <= len(c.p) (loop range), so len(c.p)-end >= 0 and the
			// uint64 comparison is exact. If v fits in the remaining buffer it
			// also fits in int, making int(v) safe on both 32- and 64-bit.
			// It also guarantees offset+length <= len(c.p) for Seek.
			end := c.offset + n + 1
			if v <= uint64(len(c.p)-end) {
				offset, length = end, int(v)
				return
			}
			break
		}
	}

	// No terminator within the window, or the payload exceeds the remaining
	// buffer. Classification (truncated vs. overflow vs. > 2 GiB) is deferred
	// to RefineErr (cold path) to keep this method inlineable.
	err = errLen
	return
}

// PeekVarint locates the varint-encoded field value at the current position
// and returns its offset and size within the input buffer. It does not
// advance the cursor; callers continue with c.Seek(off+sz). No slice is
// allocated — callers index the original buffer with data[off:off+sz].
//
// The scan window is capped at [maxVarint] (10) bytes to bound work on
// malformed input. Unlike [Cursor.PeekBytes] and [Cursor.NextTag],
// this function allows the full 10 bytes because a varint field value can
// legitimately use all 64 bits.
//
// Inlineable (cost ≤ 80).
//
// Error types (after [Cursor.RefineErr]):
//   - [io.ErrUnexpectedEOF]: the buffer ends before the varint terminates.
//   - [csproto.ErrValueOverflow]: 10 continuation bytes, or a 10th byte with
//     excess bits (bits 1-6 set at shift 63 would overflow uint64).
//
// The raw error returned by this method may be an internal sentinel and must
// be passed through [Cursor.RefineErr].
//
// Requires 0 <= c.offset <= len(c.p) on entry.
func (c Cursor) PeekVarint() (off, sz int, err error) {
	// Compute count first to avoid c.offset+maxVarint overflow on 32-bit.
	for i, b := range c.p[c.offset : c.offset+min(maxVarint, len(c.p)-c.offset)] {
		if b < 0x80 {
			// The 10th byte (i==9) is at shift 63 — only bit 0 is valid.
			// Bits 1-6 would overflow uint64; reject them.
			if i == 9 && b > 1 {
				err = csproto.ErrValueOverflow
				return
			}
			off, sz = c.offset, i+1
			return
		}
	}

	// No terminator within the window: truncated or overlong. Classification
	// is deferred to RefineErr (cold path), matching csproto.DecodeVarint.
	err = errVarintWindow
	return
}

// PeekFixed32 locates the fixed32 field value at the current position and
// returns its offset and size (always 4) within the input buffer. It does not
// advance the cursor; callers continue with c.Seek(off+sz).
//
// Inlineable. Returns [io.ErrUnexpectedEOF] if fewer than 4 bytes remain.
//
// Requires 0 <= c.offset <= len(c.p) on entry.
func (c Cursor) PeekFixed32() (off, sz int, err error) {
	return c.peekFixed(4)
}

// PeekFixed64 is the 8-byte form of [Cursor.PeekFixed32].
//
// Returns [io.ErrUnexpectedEOF] if fewer than 8 bytes remain.
func (c Cursor) PeekFixed64() (off, sz int, err error) {
	return c.peekFixed(8)
}

// peekFixed locates a fixed-width value of sz bytes. sz is a constant 4 or 8
// at every call site, so after inlining the width is folded into the bounds
// check.
func (c Cursor) peekFixed(sz int) (off, n int, err error) {
	// Use subtraction form to avoid integer overflow when c.offset is
	// near MaxInt (same rationale as PeekBytes). When len(c.p) < sz the
	// subtraction is negative, making the comparison true for any
	// non-negative c.offset — correctly returning ErrUnexpectedEOF.
	if c.offset > len(c.p)-sz {
		err = io.ErrUnexpectedEOF
		return
	}
	return c.offset, sz, nil
}

// RefineErr converts the internal sentinels returned by [Cursor.NextTag],
// [Cursor.PeekBytes] and [Cursor.PeekVarint] into an error that matches
// (with errors.Is) the public sentinel [csproto.Decoder] returns for the same
// input. [csproto.ErrInvalidFieldTag] and [csproto.ErrLenOverflow] are wrapped
// with the offending field number or length; truncation and varint overflow
// are returned bare. Other errors (and nil) pass through unchanged.
//
// It is intentionally not inlineable and runs only on the error path. Call
// it on the cursor as it was before the failing call: NextTag returns it
// unchanged on error and Peek* never advances, so c.offset still points
// at the start of the failing varint and it can be re-decoded with the
// full-fidelity [csproto.DecodeVarint].
func (c *Cursor) RefineErr(err error) error {
	switch err {
	case errTag, errLen, errVarintWindow:
	default:
		return err
	}

	if c.offset >= len(c.p) {
		// Reached when a tag is the last byte of the buffer (offset == len).
		// csproto.Decoder checks for an empty remainder before decoding and
		// returns io.ErrUnexpectedEOF; DecodeVarint on an empty slice would
		// instead return ErrInvalidVarintData.
		return io.ErrUnexpectedEOF
	}

	v, _, verr := csproto.DecodeVarint(c.p[c.offset:])
	switch {
	case verr != nil:
		// io.ErrUnexpectedEOF (truncated) or ErrValueOverflow (10+
		// continuation bytes, or 10th-byte overflow) — same as csproto.Decoder.
		// (DecodeVarint's ErrInvalidVarintData is only for an empty slice,
		// which is handled above.)
		return verr
	case err == errTag:
		// Well-formed varint, but the field number is 0 or > MaxTagValue.
		// Report the field number, matching csproto.Decoder.DecodeTag.
		return fmt.Errorf("invalid tag value (%d): %w", v>>3, csproto.ErrInvalidFieldTag)
	case v > math.MaxInt32:
		// csproto.Decoder.DecodeBytes / Skip check the 2 GiB limit before
		// checking the remaining buffer.
		return fmt.Errorf("invalid length (%d) for length-delimited field: %w", v, csproto.ErrLenOverflow)
	default:
		// errLen: a well-formed length ≤ 2 GiB that exceeds the remaining
		// buffer. (With capShifts, PeekBytes' accepted v equals the true value
		// whenever the true value ≤ 2 GiB, so this is exact.) errVarintWindow
		// never reaches here: wherever PeekVarint's 10-byte window finds no
		// terminator, DecodeVarint fails too and the verr case above returns.
		return io.ErrUnexpectedEOF
	}
}
