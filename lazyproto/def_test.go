package lazyproto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDef(t *testing.T) {
	t.Parallel()
	t.Run("new empty def", func(t *testing.T) {
		t.Parallel()

		def := NewDef()
		assert.NotNil(t, def)
		assert.Empty(t, def.m)
	})
	t.Run("new def with single tag", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1)
		assert.NotNil(t, def)
		assert.Len(t, def.m, 1)
		assert.Contains(t, def.m, int(1))
	})
	t.Run("new def with multiple tags", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1, 2, 3)
		assert.NotNil(t, def)
		assert.Len(t, def.m, 3)
		for _, tag := range []int{1, 2, 3} {
			assert.Contains(t, def.m, tag)
		}
	})
	t.Run("new def with duplicate tags", func(t *testing.T) {
		t.Parallel()

		def := NewDef(1, 2, 3, 2, 3)
		assert.NotNil(t, def)
		assert.Len(t, def.m, 3)
		for _, tag := range []int{1, 2, 3} {
			assert.Contains(t, def.m, tag)
		}
	})
	t.Run("add", func(t *testing.T) {
		t.Parallel()

		t.Run("single tag", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			def.Add(1)
			assert.Len(t, def.m, 1)
			assert.Contains(t, def.m, int(1))
			assert.Nil(t, def.m[1])
		})
		t.Run("multiple tags", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			def.Add(1, 2, 3)
			assert.Len(t, def.m, 3)
			for _, tag := range []int{1, 2, 3} {
				assert.Contains(t, def.m, tag)
			}
		})
		t.Run("duplicate tags", func(t *testing.T) {
			t.Parallel()
			t.Run("single call", func(t *testing.T) {
				t.Parallel()

				def := NewDef()
				def.Add(1, 2, 3, 2, 3)
				assert.Len(t, def.m, 3)
				for _, tag := range []int{1, 2, 3} {
					assert.Contains(t, def.m, tag)
				}
			})
			t.Run("multiple calls", func(t *testing.T) {
				t.Parallel()

				def := NewDef()
				def.Add(1, 2, 3)
				def.Add(2)
				def.Add(3)
				assert.Len(t, def.m, 3)
				for _, tag := range []int{1, 2, 3} {
					assert.Contains(t, def.m, tag)
				}
			})
		})
		t.Run("returns same instance", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			d2 := def.Add(1)
			assert.Same(t, d2, def)
		})
	})
	t.Run("add nested", func(t *testing.T) {
		t.Parallel()

		t.Run("returns new sub-def", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.AddNested(1)
			assert.NotNil(t, subdef)
			assert.NotSame(t, subdef, def)
			assert.Empty(t, subdef.m)
		})
		t.Run("single tag", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.AddNested(1, 1)
			assert.Len(t, subdef.m, 1)
			assert.Contains(t, subdef.m, int(1))
		})
		t.Run("multiple tags", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.AddNested(1, 1, 2, 3)
			assert.Len(t, subdef.m, 3)
			for _, tag := range []int{1, 2, 3} {
				assert.Contains(t, subdef.m, tag)
			}
		})
		t.Run("duplicate tags", func(t *testing.T) {
			t.Parallel()

			def := NewDef()
			subdef := def.AddNested(1, 1, 2, 3, 2, 3)
			assert.Len(t, subdef.m, 3)
			for _, tag := range []int{1, 2, 3} {
				assert.Contains(t, subdef.m, tag)
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
			subdef := def.AddNested(1)
			v, ok := def.Get(1)

			assert.NotNil(t, v)
			assert.True(t, ok)

			v2, ok := v.(*Def)
			assert.True(t, ok, "actual type of returned value should be *Def")
			assert.Same(t, v2, subdef)
		})
	})
}
