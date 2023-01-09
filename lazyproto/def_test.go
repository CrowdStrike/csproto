package lazyproto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/CrowdStrike/csproto"
)

func TestDef(t *testing.T) {
	t.Parallel()
	t.Run("new empty def", func(t *testing.T) {
		t.Parallel()

		def := NewDef()
		assert.NotNil(t, def)
		assert.Empty(t, def)
	})
	t.Run("new def with single tag", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1)
		assert.NotNil(t, def)
		assert.Len(t, def, 1)
		assert.Contains(t, def, int(1))
	})
	t.Run("new def with multiple tags", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1, 2, 3)
		assert.NotNil(t, def)
		assert.Len(t, def, 3)
		for _, tag := range []int{1, 2, 3} {
			assert.Contains(t, def, tag)
		}
	})
	t.Run("new def with duplicate tags", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1, 2, 3, 2, 3)
		assert.NotNil(t, def)
		assert.Len(t, def, 3)
		for _, tag := range []int{1, 2, 3} {
			assert.Contains(t, def, tag)
		}
	})
	t.Run("add", func(t *testing.T) {
		t.Parallel()

		t.Run("single tag", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			def.Tags(1)
			assert.Len(t, def, 1)
			assert.Contains(t, def, int(1))
			assert.Nil(t, def[1])
		})
		t.Run("multiple tags", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			def.Tags(1, 2, 3)
			assert.Len(t, def, 3)
			for _, tag := range []int{1, 2, 3} {
				assert.Contains(t, def, tag)
			}
		})
		t.Run("duplicate tags", func(t *testing.T) {
			t.Parallel()
			t.Run("single call", func(t *testing.T) {
				t.Parallel()

				def := NewDef()
				def.Tags(1, 2, 3, 2, 3)
				assert.Len(t, def, 3)
				for _, tag := range []int{1, 2, 3} {
					assert.Contains(t, def, tag)
				}
			})
			t.Run("multiple calls", func(t *testing.T) {
				t.Parallel()

				def := NewDef()
				def.Tags(1, 2, 3)
				def.Tags(2)
				def.Tags(3)
				assert.Len(t, def, 3)
				for _, tag := range []int{1, 2, 3} {
					assert.Contains(t, def, tag)
				}
			})
		})
		t.Run("returns same instance", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			d2 := def.Tags(1)
			assert.Equal(t, d2, def)
		})
	})
	t.Run("add nested", func(t *testing.T) {
		t.Parallel()

		t.Run("returns new sub-def", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.NestedTag(1)
			assert.NotNil(t, subdef)
			assert.NotSame(t, subdef, def)
			assert.Empty(t, subdef)
		})
		t.Run("single tag", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.NestedTag(1, 1)
			assert.Len(t, subdef, 1)
			assert.Contains(t, subdef, int(1))
		})
		t.Run("multiple tags", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.NestedTag(1, 1, 2, 3)
			assert.Len(t, subdef, 3)
			for _, tag := range []int{1, 2, 3} {
				assert.Contains(t, subdef, tag)
			}
		})
		t.Run("duplicate tags", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.NestedTag(1, 1, 2, 3, 2, 3)
			assert.Len(t, subdef, 3)
			for _, tag := range []int{1, 2, 3} {
				assert.Contains(t, subdef, tag)
			}
		})
	})
	t.Run("get", func(t *testing.T) {
		t.Parallel()

		t.Run("returns nil and false for missing tag", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			v, ok := def.Get(1)

			assert.Nil(t, v)
			assert.False(t, ok)
		})
		t.Run("returns nil and true for existing tag", func(t *testing.T) {
			t.Parallel()

			def := NewDef(1)
			v, ok := def.Get(1)

			assert.Nil(t, v)
			assert.True(t, ok)
		})
		t.Run("returns Def and true for existing nested tag", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.NestedTag(1)
			v, ok := def.Get(1)

			assert.NotNil(t, v)
			assert.True(t, ok)
			assert.Equal(t, v, subdef)
		})
	})
}

func TestDefValidation(t *testing.T) {
	t.Parallel()
	t.Run("valid def", func(t *testing.T) {
		t.Parallel()
		t.Run("without nesting", func(t *testing.T) {
			t.Parallel()
			def := NewDef(1, 2, 3)

			err := def.Validate()
			assert.NoError(t, err)
		})
		t.Run("with nesting", func(t *testing.T) {
			t.Parallel()
			def := NewDef(1, 2, 3)
			_ = def.NestedTag(4, 5, 6, 7)

			err := def.Validate()
			assert.NoError(t, err)
		})
	})
	t.Run("invalid def", func(t *testing.T) {
		t.Parallel()
		t.Run("negative tag", func(t *testing.T) {
			t.Parallel()
			def := NewDef(-1)

			err := def.Validate()
			assert.Error(t, err)
			assert.Equal(t, "invalid field tag (-1) at path []", err.Error())
		})
		t.Run("positive tag overflow", func(t *testing.T) {
			t.Parallel()
			def := NewDef(csproto.MaxTagValue + 1)

			err := def.Validate()
			assert.Error(t, err)
			assert.Equal(t, fmt.Sprintf("invalid field tag (%d) at path []", csproto.MaxTagValue+1), err.Error())
		})
		t.Run("reserved tags", func(t *testing.T) {
			t.Parallel()
			for i := protowire.FirstReservedNumber; i <= protowire.LastReservedNumber; i++ {
				def := NewDef(int(i))

				err := def.Validate()
				assert.Error(t, err)
				assert.Equal(t, fmt.Sprintf("invalid field tag (%d) at path []", int(i)), err.Error())
			}
		})
		t.Run("nested", func(t *testing.T) {
			t.Parallel()
			t.Run("negative tag", func(t *testing.T) {
				t.Parallel()
				def := NewDef()
				subdef := def.NestedTag(1)
				_ = subdef.NestedTag(2, -1)

				err := def.Validate()
				assert.Error(t, err)
				assert.Equal(t, "invalid field tag (-1) at path [1 2]", err.Error())
			})
			t.Run("positive tag overflow", func(t *testing.T) {
				t.Parallel()
				def := NewDef()
				subdef := def.NestedTag(1)
				_ = subdef.NestedTag(2, csproto.MaxTagValue+1)

				err := def.Validate()
				assert.Error(t, err)
				assert.Equal(t, fmt.Sprintf("invalid field tag (%d) at path [1 2]", csproto.MaxTagValue+1), err.Error())
			})
			t.Run("reserved tags", func(t *testing.T) {
				t.Parallel()
				for i := protowire.FirstReservedNumber; i <= protowire.LastReservedNumber; i++ {
					def := NewDef()
					subdef := def.NestedTag(1)
					_ = subdef.NestedTag(2, int(i))

					err := def.Validate()
					assert.Error(t, err)
					assert.Equal(t, fmt.Sprintf("invalid field tag (%d) at path [1 2]", int(i)), err.Error())
				}
			})
		})
	})
}
