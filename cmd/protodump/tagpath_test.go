package main

import (
	"flag"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CrowdStrike/csproto"
)

func Example_tagPaths() {
	// This example covers using a tagPaths variable with the standard library flag package
	// to parse tag paths from the command line.

	// declare and register the flag value
	var tp tagPaths
	fset := flag.NewFlagSet("test", flag.ExitOnError)
	fset.Var(&tp, "paths", "")

	// parse the "command line"
	// - in real code this would be fset.Parse(os.Args[1:])
	err := fset.Parse([]string{"-paths", "1,2,3", "-paths", "1.2", "-paths", "3.4", "-paths", "5.6"})
	if err != nil {
		fmt.Printf("error parsing args: %v\n", err)
	}

	// should have parsed 6 values, 3 from the first -paths param and 1 each from the other 3
	fmt.Printf("results: %s", tp.String())
	// Output: results: [1,2,3,1.2,3.4,5.6]
}

func TestTagPathArgParse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		input      string
		shouldFail bool
		expected   []tagPath
	}{
		// success cases
		{"empty", "", false, nil},
		{"single value", "1", false, []tagPath{{1}}},
		{"multiple single values", "1,2", false, []tagPath{{1}, {2}}},
		{"single dotted value", "1.2", false, []tagPath{{1, 2}}},
		{"multiple dotted values", "1.2,3.4", false, []tagPath{{1, 2}, {3, 4}}},
		// failure cases
		{"single non-integer value", "x", true, nil},
		{"single non-integer dotted value", "1.x", true, nil},
		{"multiple single values with non-integer", "1,2,x", true, nil},
		{"multiple dotted values with non-integer", "1.2,3.4,5.x", true, nil},
		{"invalid integer value/underflow", "-1", true, nil},
		{"invalid integer value/overflow", strconv.Itoa(csproto.MaxTagValue + 1), true, nil},
		// edge cases
		{"leading comma", ",1,2,3", false, []tagPath{{1}, {2}, {3}}},
		{"trailing comma", "1,2,3,", false, []tagPath{{1}, {2}, {3}}},
		{"multiple values with empty item", "1,,2.3", false, []tagPath{{1}, {2, 3}}},
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
				assert.Equal(t, tc.expected, ev.paths, "argument parsing incorrect")
			}
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
