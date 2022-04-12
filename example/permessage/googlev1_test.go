package permessage_test

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/CrowdStrike/csproto"
	"github.com/CrowdStrike/csproto/example/permessage/googlev1"
)

func TestMapFieldsUnmarshalAfterGoogleV1Marshal(t *testing.T) {
	var msg, msg2 googlev1.AllTheMaps

	msg = googlev1.AllTheMaps{
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
		ToMessage:  map[string]*googlev1.EmbeddedEvent{"one": {ID: 1}, "two": {ID: 2}},
		ToEnum:     map[string]googlev1.EventType{"one": googlev1.EventType_EVENT_TYPE_ONE, "two": googlev1.EventType_EVENT_TYPE_TWO},
	}
	data, _ := proto.Marshal(&msg)

	err := csproto.Unmarshal(data, &msg2)
	assert.NoError(t, err)
	diff := cmp.Diff(&msg, &msg2, protocmp.Transform())
	assert.Empty(t, diff, "diff between messages should be empty")
}

func TestGoogleV1UnmarshalMapFieldsAfterCustomMarshal(t *testing.T) {
	var msg, msg2 googlev1.AllTheMaps

	msg = googlev1.AllTheMaps{
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
		ToMessage:  map[string]*googlev1.EmbeddedEvent{"one": {ID: 1}, "two": {ID: 2}},
		ToEnum:     map[string]googlev1.EventType{"one": googlev1.EventType_EVENT_TYPE_ONE, "two": googlev1.EventType_EVENT_TYPE_TWO},
	}
	data, _ := csproto.Marshal(&msg)

	err := proto.Unmarshal(data, &msg2)
	assert.NoError(t, err)
	diff := cmp.Diff(&msg, &msg2, protocmp.Transform())
	assert.Empty(t, diff, "diff between messages should be empty")
}
