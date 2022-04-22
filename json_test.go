package csproto_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
)

func TestMarshalJSON(t *testing.T) {
	// using timestamppb.Timestamp because it's a readily available Protobuf message with a simple structure
	//
	// TODO: dylan-bourque (2022-04-22)
	// find another simple, readily available message that contains an enum field to test JSONOptions.UseEnumNumbers
	// . none of Google's WKT messages fit the bill :(
	t.Run("default", func(t *testing.T) {
		ts := timestamppb.Now()
		expected := fmt.Sprintf(`{"seconds":"%d","nanos":%d}`, ts.GetSeconds(), ts.GetNanos())

		res, err := csproto.JSONMarshaler(ts).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		ts := timestamppb.Now()
		expected := fmt.Sprintf("{\n  \"seconds\":\"%d\",\n  \"nanos\":%d\n}", ts.GetSeconds(), ts.GetNanos())

		opts := []csproto.JSONOption{
			csproto.JSONIndent("  "),
		}
		res, err := csproto.JSONMarshaler(ts, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("exclude-zero-values", func(t *testing.T) {
		ts := timestamppb.Now()
		ts.Nanos = 0
		expected := fmt.Sprintf(`{"seconds":"%d"}`, ts.GetSeconds())

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(false),
		}
		res, err := csproto.JSONMarshaler(ts, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("include-zero-values", func(t *testing.T) {
		ts := timestamppb.Now()
		ts.Nanos = 0
		expected := fmt.Sprintf(`{"seconds":"%d","nanos":0}`, ts.GetSeconds())

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(true),
		}
		res, err := csproto.JSONMarshaler(ts, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("enable-all", func(t *testing.T) {
		ts := timestamppb.Now()
		ts.Nanos = 0
		expected := fmt.Sprintf("{\n  \"seconds\":\"%d\",\n  \"nanos\":0\n}", ts.GetSeconds())

		opts := []csproto.JSONOption{
			csproto.JSONIndent("  "),
			csproto.JSONIncludeZeroValues(true),
			csproto.JSONUseEnumNumbers(true),
		}
		res, err := csproto.JSONMarshaler(ts, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
}
