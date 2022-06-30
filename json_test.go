package csproto_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/testproto"
)

// encodedTimeFormat is the expected JSON encoded string format of timestamppb.
// https://github.com/protocolbuffers/protobuf-go/blob/32051b4f86e54c2142c7c05362c6e96ae3454a1c/encoding/protojson/well_known_types.go#L764-L775
const encodedTimeFormat = "2006-01-02T15:04:05.000000Z"

func TestMarshalJSON(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		msg := &testproto.Test{
			Name: "John",
			Age:  21,
			Ts:   timestamppb.Now(),
		}
		expected := fmt.Sprintf("{\"name\":\"%s\",\"age\":%d,\"ts\":\"%s\"}",
			msg.Name, msg.Age, msg.Ts.AsTime().Format(encodedTimeFormat))

		res, err := csproto.JSONMarshaler(msg).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("with-indent", func(t *testing.T) {
		msg := &testproto.Test{
			Name: "John",
			Age:  21,
			Ts:   timestamppb.Now(),
		}
		expected := fmt.Sprintf("{\n\t\"name\":\"%s\",\t\"age\":%d,\t\"ts\":\"%s\"\t}",
			msg.Name, msg.Age, msg.Ts.AsTime().Format(encodedTimeFormat))

		opts := []csproto.JSONOption{
			csproto.JSONIndent("\t"),
		}
		res, err := csproto.JSONMarshaler(msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("exclude-zero-values", func(t *testing.T) {
		msg := &testproto.Test{
			Name: "John",
			Age:  0,
			Ts:   timestamppb.Now(),
		}
		expected := fmt.Sprintf("{\n\t\"name\":\"%s\",\t\t\"ts\":\"%s\"\t}",
			msg.Name, msg.Ts.AsTime().Format(encodedTimeFormat))

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(false),
		}
		res, err := csproto.JSONMarshaler(msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("include-zero-values", func(t *testing.T) {
		msg := &testproto.Test{
			Name: "John",
			Age:  0,
			Ts:   timestamppb.Now(),
		}
		expected := fmt.Sprintf("{\n\t\"name\":\"%s\",\t\"age\":%d,\t\"status\":\"UNKNOWN\",\t\"ts\":\"%s\"\t}",
			msg.Name, msg.Age, msg.Ts.AsTime().Format(encodedTimeFormat))

		opts := []csproto.JSONOption{
			csproto.JSONIncludeZeroValues(true),
		}
		res, err := csproto.JSONMarshaler(msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("dont-use-enum-numbers", func(t *testing.T) {
		msg := &testproto.Test{
			Name:   "John",
			Age:    21,
			Status: testproto.Test_PRESENT,
			Ts:     timestamppb.Now(),
		}
		expected := fmt.Sprintf("{\n\t\"name\":\"%s\",\t\"age\":%d,\t\"status\":\"%s\",\t\"ts\":\"%s\"\t}",
			msg.Name, msg.Age, testproto.Test_Status_name[int32(msg.Status)], msg.Ts.AsTime().Format(encodedTimeFormat))

		opts := []csproto.JSONOption{
			csproto.JSONUseEnumNumbers(false),
		}
		res, err := csproto.JSONMarshaler(msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("use-enum-numbers", func(t *testing.T) {
		msg := &testproto.Test{
			Name:   "John",
			Age:    21,
			Status: testproto.Test_PRESENT,
			Ts:     timestamppb.Now(),
		}
		expected := fmt.Sprintf("{\n\t\"name\":\"%s\",\t\"age\":%d,\t\"status\":%d,\t\"ts\":\"%s\"\t}",
			msg.Name, msg.Age, msg.Status, msg.Ts.AsTime().Format(encodedTimeFormat))

		opts := []csproto.JSONOption{
			csproto.JSONUseEnumNumbers(true),
		}
		res, err := csproto.JSONMarshaler(msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
	t.Run("enable-all", func(t *testing.T) {
		msg := &testproto.Test{
			Name:   "John",
			Age:    0,
			Status: testproto.Test_GONE,
			Ts:     timestamppb.Now(),
		}
		expected := fmt.Sprintf("{\n\t\"name\":\"%s\",\t\"age\":%d,\t\"status\":%d,\t\"ts\":\"%s\"\t}",
			msg.Name, msg.Age, msg.Status, msg.Ts.AsTime().Format(encodedTimeFormat))

		opts := []csproto.JSONOption{
			csproto.JSONIndent("  "),
			csproto.JSONIncludeZeroValues(true),
			csproto.JSONUseEnumNumbers(true),
		}
		res, err := csproto.JSONMarshaler(msg, opts...).MarshalJSON()

		assert.NoError(t, err)
		assert.JSONEq(t, expected, string(res))
	})
}
