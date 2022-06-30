package csproto_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
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
		// https://github.com/protocolbuffers/protobuf-go/blob/32051b4f86e54c2142c7c05362c6e96ae3454a1c/encoding/protojson/well_known_types.go#L764-L775
		expected := fmt.Sprintf("\"%s\"", ts.AsTime().Format("2006-01-02T15:04:05.000000Z"))

		res, err := csproto.JSONMarshaler(ts).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		input, err := structpb.NewValue(map[string]interface{}{
			"firstName": "John",
			"lastName":  "Smith",
		})
		assert.NoError(t, err)

		expected := "{\n  \"firstName\":\"John\",\n  \"lastName\":\"Smith\"\n}"

		opts := []csproto.JSONOption{
			csproto.JSONIndent("  "),
		}
		res, err := csproto.JSONMarshaler(input, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("exclude-zero-values", func(t *testing.T) {
		input, err := structpb.NewValue(map[string]interface{}{
			"firstName": "John",
			"lastName":  "Smith",
			"location":  nil,
		})
		assert.NoError(t, err)

		expected := "{\n  \"firstName\":\"John\",\n  \"lastName\":\"Smith\"\n}"

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(false),
		}
		res, err := csproto.JSONMarshaler(input, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("include-zero-values", func(t *testing.T) {
		input, err := structpb.NewValue(map[string]interface{}{
			"firstName": "John",
			"lastName":  "Smith",
			"location":  nil,
		})
		assert.NoError(t, err)

		expected := "{\n  \"firstName\":\"John\",\n  \"lastName\":\"Smith\"\n  \"location\":null\n}"

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(true),
		}
		res, err := csproto.JSONMarshaler(input, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("enable-all", func(t *testing.T) {
		input, err := structpb.NewValue(map[string]interface{}{
			"firstName": "John",
			"lastName":  "Smith",
		})
		assert.NoError(t, err)

		expected := "{\n  \"firstName\":\"John\",\n  \"lastName\":\"Smith\"\n}"

		opts := []csproto.JSONOption{
			csproto.JSONIndent("  "),
			csproto.JSONIncludeZeroValues(true),
			csproto.JSONUseEnumNumbers(true),
		}
		res, err := csproto.JSONMarshaler(input, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
}
