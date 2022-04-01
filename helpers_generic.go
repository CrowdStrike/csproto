//go:build go1.18
// +build go1.18

package csproto

// NativeTypes defines a generic constraint for the native Go types that need to be converted to
// pointers when storing values in generated Protobuf message structs.
//
// Unsized integers (type int) also need to be converted to a pointer, but Protobuf doesn't support
// unsized integers.  Use csproto.Int(v int) *int32 instead.
type NativeTypes interface {
	bool | int32 | int64 | uint32 | uint64 | float32 | float64 | string
}

// PointerTo makes a copy of v and returns a pointer to that copy
func PointerTo[T NativeTypes](v T) *T {
	return &v
}
