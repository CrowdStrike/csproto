package permessage_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/permessage/gogo"
)

func TestMapFieldsUnmarshalAfterGogoMarshal(t *testing.T) {
	var msg, msg2 gogo.AllTheMaps

	msg = gogo.AllTheMaps{
		ToInt32:    map[string]int32{"one": 1, "two": 2},
		ToInt64:    map[string]int64{"one": 1, "two": 2},
		ToUInt32:   map[string]uint32{"one": 1, "two": 2},
		ToUInt64:   map[string]uint64{"one": 1, "two": 2},
		ToString:   map[string]string{"one": "1", "two": "2"},
		ToBytes:    map[string][]byte{"one": {0x1, 0x2, 0x3}, "two": {0x4, 0x5, 0x6}},
		ToSInt32:   map[string]int32{"one": 1, "two": 2},
		ToSInt64:   map[string]int64{"one": 1, "two": 2},
		ToFixed32:  map[string]uint32{"one": 1, "two": 2},
		ToSFixed32: map[string]int32{"one": 1, "two": 2},
		ToFixed64:  map[string]uint64{"one": 1, "two": 2},
		ToSFixed64: map[string]int64{"one": 1, "two": 2},
		ToFloat:    map[string]float32{"one": 1.0, "two": 2.0},
		ToDouble:   map[string]float64{"one": 1.0, "two": 2.0},
		ToMessage:  map[string]*gogo.EmbeddedEvent{"one": {ID: 1}, "two": {ID: 2}},
		ToEnum:     map[string]gogo.EventType{"one": gogo.EventType_EVENT_TYPE_ONE, "two": gogo.EventType_EVENT_TYPE_TWO},
	}
	data, _ := proto.Marshal(&msg)

	err := csproto.Unmarshal(data, &msg2)
	assert.NoError(t, err)
	diff := cmp.Diff(msg, msg2, protocmp.Transform())
	assert.Empty(t, diff, "diff between messages should be empty")
}

func TestGogoUnmarshalMapFieldsAfterCustomMarshal(t *testing.T) {
	var msg, msg2 gogo.AllTheMaps

	msg = gogo.AllTheMaps{
		ToInt32:    map[string]int32{"one": 1, "two": 2},
		ToInt64:    map[string]int64{"one": 1, "two": 2},
		ToUInt32:   map[string]uint32{"one": 1, "two": 2},
		ToUInt64:   map[string]uint64{"one": 1, "two": 2},
		ToString:   map[string]string{"one": "1", "two": "2"},
		ToBytes:    map[string][]byte{"one": {0x1, 0x2, 0x3}, "two": {0x4, 0x5, 0x6}},
		ToSInt32:   map[string]int32{"one": 1, "two": 2},
		ToSInt64:   map[string]int64{"one": 1, "two": 2},
		ToFixed32:  map[string]uint32{"one": 1, "two": 2},
		ToSFixed32: map[string]int32{"one": 1, "two": 2},
		ToFixed64:  map[string]uint64{"one": 1, "two": 2},
		ToSFixed64: map[string]int64{"one": 1, "two": 2},
		ToFloat:    map[string]float32{"one": 1.0, "two": 2.0},
		ToDouble:   map[string]float64{"one": 1.0, "two": 2.0},
		ToMessage:  map[string]*gogo.EmbeddedEvent{"one": {ID: 1}, "two": {ID: 2}},
		ToEnum:     map[string]gogo.EventType{"one": gogo.EventType_EVENT_TYPE_ONE, "two": gogo.EventType_EVENT_TYPE_TWO},
	}
	data, _ := csproto.Marshal(&msg)
	fmt.Fprint(os.Stderr, "[")
	for _, b := range data {
		fmt.Fprintf(os.Stderr, "0x%x ", b)
	}
	fmt.Fprintf(os.Stderr, "]\n")

	err := proto.Unmarshal(data, &msg2)
	assert.NoError(t, err)
	diff := cmp.Diff(msg, msg2, protocmp.Transform())
	assert.Empty(t, diff, "diff between messages should be empty")
}
