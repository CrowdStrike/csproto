// GENERATED CODE - DO NOT EDIT
// This file was generated by protoc-gen-fastmarshal

package gogo

import (
	"fmt"
	"sync/atomic"
	"github.com/CrowdStrike/csproto"
)

//------------------------------------------------------------------------------
// Custom Protobuf size/marshal/unmarshal code for I18NVariable

// Size calculates and returns the size, in bytes, required to hold the contents of m using the Protobuf
// binary encoding.
func (m *I18NVariable) Size() int {
	// nil message is always 0 bytes
	if m == nil {
		return 0
	}
	// return cached size, if present
	if csz := int(atomic.LoadInt32(&m.XXX_sizecache)); csz > 0 {
		return csz
	}
	// calculate and cache
	var sz, l int
	_ = l // avoid unused variable

	// OneOfValues (oneof)
	if m.OneOfValues != nil {
		switch typedVal := m.OneOfValues.(type) {
		case *I18NVariable_OptOne: // opt_one (1,string)
			l = len(typedVal.OptOne)
			sz += csproto.SizeOfTagKey(1) + csproto.SizeOfVarint(uint64(l)) + l
		case *I18NVariable_OptTwo: // opt_two (2,string)
			l = len(typedVal.OptTwo)
			sz += csproto.SizeOfTagKey(2) + csproto.SizeOfVarint(uint64(l)) + l
		default:
			_ = typedVal // ensure no unused variable
		}
	}

	// cache the size so it can be re-used in Marshal()/MarshalTo()
	atomic.StoreInt32(&m.XXX_sizecache, int32(sz))
	return sz
}

// Marshal converts the contents of m to the Protobuf binary encoding and returns the result or an error.
func (m *I18NVariable) Marshal() ([]byte, error) {
	siz := m.Size()
	if siz == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, siz)
	err := m.MarshalTo(buf)
	return buf, err
}

// MarshalTo converts the contents of m to the Protobuf binary encoding and writes the result to dest.
func (m *I18NVariable) MarshalTo(dest []byte) error {
	// nil message == no-op
	if m == nil {
		return nil
	}
	var (
		enc    = csproto.NewEncoder(dest)
		buf    []byte
		err    error
		extVal interface{}
	)
	// ensure no unused variables
	_ = enc
	_ = buf
	_ = err
	_ = extVal

	// OneOfValues (oneof)

	if m.OneOfValues != nil {
		switch typedVal := m.OneOfValues.(type) {
		case *I18NVariable_OptOne: // opt_one (1,string)
			enc.EncodeString(1, typedVal.OptOne)
		case *I18NVariable_OptTwo: // opt_two (2,string)
			enc.EncodeString(2, typedVal.OptTwo)
		default:
			_ = typedVal // ensure no unused variable
		}
	}
	return nil
}

// Unmarshal decodes a binary encoded Protobuf message from p and populates m with the result.
func (m *I18NVariable) Unmarshal(p []byte) error {
	m.Reset()
	if len(p) == 0 {
		return nil
	}
	dec := csproto.NewDecoder(p)
	for dec.More() {
		tag, wt, err := dec.DecodeTag()
		if err != nil {
			return err
		}
		switch tag {

		case 1: // one_of_values.opt_one (oneof,string)
			var ov I18NVariable_OptOne
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for tag field 'opt_one' (tag=1), expected 2 (length-delimited)", wt)
			}
			if s, err := dec.DecodeString(); err != nil {
				return fmt.Errorf("unable to decode string value for field 'opt_one' (tag=1): %w", err)
			} else {
				ov.OptOne = s
			}
			m.OneOfValues = &ov
		case 2: // one_of_values.opt_two (oneof,string)
			var ov I18NVariable_OptTwo
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for tag field 'opt_two' (tag=2), expected 2 (length-delimited)", wt)
			}
			if s, err := dec.DecodeString(); err != nil {
				return fmt.Errorf("unable to decode string value for field 'opt_two' (tag=2): %w", err)
			} else {
				ov.OptTwo = s
			}
			m.OneOfValues = &ov
		default:
			if skipped, err := dec.Skip(tag, wt); err != nil {
				return fmt.Errorf("invalid operation skipping tag %v: %w", tag, err)
			} else {
				m.XXX_unrecognized = append(m.XXX_unrecognized, skipped...)
			}
		}
	}
	return nil
}