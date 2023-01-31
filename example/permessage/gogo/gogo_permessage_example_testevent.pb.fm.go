// GENERATED CODE - DO NOT EDIT
// This file was generated by protoc-gen-fastmarshal

package gogo

import (
	"fmt"
	"sync/atomic"
	"github.com/CrowdStrike/csproto"
	"github.com/gogo/protobuf/types"
)

//------------------------------------------------------------------------------
// Custom Protobuf size/marshal/unmarshal code for TestEvent

// Size calculates and returns the size, in bytes, required to hold the contents of m using the Protobuf
// binary encoding.
func (m *TestEvent) Size() int {
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

	// Name (string,optional)
	if l = len(m.Name); l > 0 {
		sz += csproto.SizeOfTagKey(1) + csproto.SizeOfVarint(uint64(l)) + l
	}
	// Info (string,optional)
	if l = len(m.Info); l > 0 {
		sz += csproto.SizeOfTagKey(2) + csproto.SizeOfVarint(uint64(l)) + l
	}
	// IsAwesome (bool,optional)
	if m.IsAwesome {
		sz += csproto.SizeOfTagKey(3) + 1
	}
	// Labels (string,repeated)
	for _, sv := range m.Labels {
		l = len(sv)
		sz += csproto.SizeOfTagKey(4) + csproto.SizeOfVarint(uint64(l)) + l
	}
	// Embedded (message,optional)
	if m.Embedded != nil {
		l = csproto.Size(m.Embedded)
		sz += csproto.SizeOfTagKey(5) + csproto.SizeOfVarint(uint64(l)) + l
	}
	// Nested (message,optional)
	if m.Nested != nil {
		l = csproto.Size(m.Nested)
		sz += csproto.SizeOfTagKey(9) + csproto.SizeOfVarint(uint64(l)) + l
	}
	// Ts (message,optional)
	if m.Ts != nil {
		l = csproto.Size(m.Ts)
		sz += csproto.SizeOfTagKey(10) + csproto.SizeOfVarint(uint64(l)) + l
	}
	// Path (oneof)
	if m.Path != nil {
		switch typedVal := m.Path.(type) {
		case *TestEvent_Jedi: // jedi (6,bool)
			sz += csproto.SizeOfTagKey(6) + 1
		case *TestEvent_Sith: // sith (7,bool)
			sz += csproto.SizeOfTagKey(7) + 1
		case *TestEvent_Other: // other (8,string)
			l = len(typedVal.Other)
			sz += csproto.SizeOfTagKey(8) + csproto.SizeOfVarint(uint64(l)) + l
		default:
			_ = typedVal // ensure no unused variable
		}
	}

	// cache the size so it can be re-used in Marshal()/MarshalTo()
	atomic.StoreInt32(&m.XXX_sizecache, int32(sz))
	return sz
}

// Marshal converts the contents of m to the Protobuf binary encoding and returns the result or an error.
func (m *TestEvent) Marshal() ([]byte, error) {
	siz := m.Size()
	if siz == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, siz)
	err := m.MarshalTo(buf)
	return buf, err
}

// MarshalTo converts the contents of m to the Protobuf binary encoding and writes the result to dest.
func (m *TestEvent) MarshalTo(dest []byte) error {
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

	// Name (1,string,optional)
	if len(m.Name) > 0 {
		enc.EncodeString(1, m.Name)
	}
	// Info (2,string,optional)
	if len(m.Info) > 0 {
		enc.EncodeString(2, m.Info)
	}
	// IsAwesome (3,bool,optional)
	if m.IsAwesome {
		enc.EncodeBool(3, m.IsAwesome)
	}
	// Labels (4,string,repeated)
	for _, val := range m.Labels {
		enc.EncodeString(4, val)
	}
	// Embedded (5,message,optional)
	if m.Embedded != nil {
		if err = enc.EncodeNested(5, m.Embedded); err != nil {
			return fmt.Errorf("unable to encode message data for field 'embedded' (tag=5): %w", err)
		}
	}
	// Nested (9,message,optional)
	if m.Nested != nil {
		if err = enc.EncodeNested(9, m.Nested); err != nil {
			return fmt.Errorf("unable to encode message data for field 'nested' (tag=9): %w", err)
		}
	}
	// Ts (10,message,optional)
	if m.Ts != nil {
		if err = enc.EncodeNested(10, m.Ts); err != nil {
			return fmt.Errorf("unable to encode message data for field 'ts' (tag=10): %w", err)
		}
	}
	// Path (oneof)
	if m.Path != nil {
		switch typedVal := m.Path.(type) {
		case *TestEvent_Jedi: // jedi (6,bool)
			enc.EncodeBool(6, typedVal.Jedi)
		case *TestEvent_Sith: // sith (7,bool)
			enc.EncodeBool(7, typedVal.Sith)
		case *TestEvent_Other: // other (8,string)
			enc.EncodeString(8, typedVal.Other)
		default:
			_ = typedVal // ensure no unused variable
		}
	}
	return nil
}

// Unmarshal decodes a binary encoded Protobuf message from p and populates m with the result.
func (m *TestEvent) Unmarshal(p []byte) error {
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
		case 1: // Name (string,optional)
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for field 'name' (tag=1), expected 2 (length-delimited)", wt)
			}
			if s, err := dec.DecodeString(); err != nil {
				return fmt.Errorf("unable to decode string value for field 'name' (tag=1): %w", err)
			} else {
				m.Name = s
			}

		case 2: // Info (string,optional)
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for field 'info' (tag=2), expected 2 (length-delimited)", wt)
			}
			if s, err := dec.DecodeString(); err != nil {
				return fmt.Errorf("unable to decode string value for field 'info' (tag=2): %w", err)
			} else {
				m.Info = s
			}

		case 3: // IsAwesome (bool,optional)
			if wt != csproto.WireTypeVarint {
				return fmt.Errorf("incorrect wire type %v for tag field 'isAwesome' (tag=3), expected 0 (varint)", wt)
			}
			if v, err := dec.DecodeBool(); err != nil {
				return fmt.Errorf("unable to decode boolean value for field 'isAwesome' (tag=3): %w", err)
			} else {
				m.IsAwesome = v
			}
		case 4: // Labels (string,repeated)
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for field 'labels' (tag=4), expected 2 (length-delimited)", wt)
			}
			if s, err := dec.DecodeString(); err != nil {
				return fmt.Errorf("unable to decode string value for field 'labels' (tag=4): %w", err)
			} else {
				m.Labels = append(m.Labels, s)
			}

		case 5: // Embedded (message,optional)
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for field 'embedded' (tag=5), expected 2 (length-delimited)", wt)
			}
			var mm EmbeddedEvent
			if err = dec.DecodeNested(&mm); err != nil {
				return fmt.Errorf("unable to decode message value for field 'embedded' (tag=5): %w", err)
			}
			m.Embedded = &mm

		case 9: // Nested (message,optional)
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for field 'nested' (tag=9), expected 2 (length-delimited)", wt)
			}
			var mm TestEvent_NestedMsg
			if err = dec.DecodeNested(&mm); err != nil {
				return fmt.Errorf("unable to decode message value for field 'nested' (tag=9): %w", err)
			}
			m.Nested = &mm
		case 10: // Ts (message,optional)
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for field 'ts' (tag=10), expected 2 (length-delimited)", wt)
			}
			var mm types.Timestamp
			if err = dec.DecodeNested(&mm); err != nil {
				return fmt.Errorf("unable to decode message value for field 'ts' (tag=10): %w", err)
			}
			m.Ts = &mm

		case 6: // path.jedi (oneof,bool)
			var ov TestEvent_Jedi
			if wt != csproto.WireTypeVarint {
				return fmt.Errorf("incorrect wire type %v for tag field 'jedi' (tag=6), expected 0 (varint)", wt)
			}
			if v, err := dec.DecodeBool(); err != nil {
				return fmt.Errorf("unable to decode boolean value for field 'jedi' (tag=6): %w", err)
			} else {
				ov.Jedi = v
			}
			m.Path = &ov
		case 7: // path.sith (oneof,bool)
			var ov TestEvent_Sith
			if wt != csproto.WireTypeVarint {
				return fmt.Errorf("incorrect wire type %v for tag field 'sith' (tag=7), expected 0 (varint)", wt)
			}
			if v, err := dec.DecodeBool(); err != nil {
				return fmt.Errorf("unable to decode boolean value for field 'sith' (tag=7): %w", err)
			} else {
				ov.Sith = v
			}
			m.Path = &ov
		case 8: // path.other (oneof,string)
			var ov TestEvent_Other
			if wt != csproto.WireTypeLengthDelimited {
				return fmt.Errorf("incorrect wire type %v for tag field 'other' (tag=8), expected 2 (length-delimited)", wt)
			}
			if s, err := dec.DecodeString(); err != nil {
				return fmt.Errorf("unable to decode string value for field 'other' (tag=8): %w", err)
			} else {
				ov.Other = s
			}
			m.Path = &ov
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
