package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTagPathArgParse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		input      string
		shouldFail bool
		expected   []tagPath
	}{
		{"empty", "", false, nil},
		{"single value", "1", false, []tagPath{{1}}},
		{"multiple single values", "1,2", false, []tagPath{{1}, {2}}},
		{"single dotted value", "1.2", false, []tagPath{{1, 2}}},
		{"multiple dotted values", "1.2,3.4", false, []tagPath{{1, 2}, {3, 4}}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ev tagPaths
			err := ev.Set(tc.input)

			if tc.shouldFail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expected, ev.paths, "argument parsing incorrect")
		})
	}
}

func TestTagPathMatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		tp          tagPath
		against     tagPath
		shouldMatch bool
	}{
		{
			name:        "empty path does not match empty path",
			tp:          tagPath{},
			against:     tagPath{},
			shouldMatch: false,
		},
		{
			name:        "empty path does not match non-empty path",
			tp:          tagPath{},
			against:     tagPath{1},
			shouldMatch: false,
		},
		{
			name:        "non-empty path does not match longer path",
			tp:          tagPath{1},
			against:     tagPath{1, 2},
			shouldMatch: false,
		},
		{
			name:        "non-empty path does not match shorter path",
			tp:          tagPath{1, 2},
			against:     tagPath{1},
			shouldMatch: false,
		},
		{
			name:        "mismatched path does not match",
			tp:          tagPath{1, 2, 3, 4},
			against:     tagPath{1, 2, 3, 5},
			shouldMatch: false,
		},
		{
			name:        "single node path matches",
			tp:          tagPath{1},
			against:     tagPath{1},
			shouldMatch: true,
		},
		{
			name:        "multiple node path matches",
			tp:          tagPath{1, 2, 3},
			against:     tagPath{1, 2, 3},
			shouldMatch: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.tp.Matches(tc.against)
			assert.Equal(t, tc.shouldMatch, got)
		})
	}
}
