package csproto_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CrowdStrike/csproto"
)

func TestSizeOfVarint(t *testing.T) {
	cases := []struct {
		name     string
		v        uint64
		expected int
	}{
		{
			name:     "min value",
			v:        1,
			expected: 1,
		},
		{
			name:     "2^7-1",
			v:        (1 << 7) - 1,
			expected: 1,
		},
		{
			name:     "2^7",
			v:        (1 << 7),
			expected: 2,
		},
		{
			name:     "2^14-1",
			v:        (1 << 14) - 1,
			expected: 2,
		},
		{
			name:     "2^14",
			v:        (1 << 14),
			expected: 3,
		},
		{
			name:     "2^21-1",
			v:        (1 << 21) - 1,
			expected: 3,
		},
		{
			name:     "2^21",
			v:        (1 << 21),
			expected: 4,
		},
		{
			name:     "2^28-1",
			v:        (1 << 28) - 1,
			expected: 4,
		},
		{
			name:     "2^28",
			v:        (1 << 28),
			expected: 5,
		},
		{
			name:     "2^35-1",
			v:        (1 << 35) - 1,
			expected: 5,
		},
		{
			name:     "2^35",
			v:        (1 << 35),
			expected: 6,
		},
		{
			name:     "2^42-1",
			v:        (1 << 42) - 1,
			expected: 6,
		},
		{
			name:     "2^42",
			v:        (1 << 42),
			expected: 7,
		},
		{
			name:     "2^49-1",
			v:        (1 << 49) - 1,
			expected: 7,
		},
		{
			name:     "2^49",
			v:        (1 << 49),
			expected: 8,
		},
		{
			name:     "2^56-1",
			v:        (1 << 56) - 1,
			expected: 8,
		},
		{
			name:     "2^56",
			v:        (1 << 56),
			expected: 9,
		},
		{
			name:     "2^63-1",
			v:        (1 << 63) - 1,
			expected: 9,
		},
		{
			name:     "2^63",
			v:        (1 << 63),
			expected: 10,
		},
		{
			name:     "math.MaxUInt64",
			v:        math.MaxUint64,
			expected: 10,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := csproto.SizeOfVarint(tc.v)
			assert.Equal(t, tc.expected, got)
		})
	}
}
