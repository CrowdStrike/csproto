package csproto

import (
	gogo "github.com/gogo/protobuf/proto"
	googlev1 "github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	googlev2 "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"reflect"
	"testing"
)

type GogoMessage struct{}

func (m GogoMessage) Reset()         {}
func (m GogoMessage) String() string { return "" }
func (m GogoMessage) ProtoMessage()  {}

var _ gogo.Message = &GogoMessage{}

type GoogleV1Message struct{ Text string }

func (m GoogleV1Message) Reset()         {}
func (m GoogleV1Message) String() string { return "" }
func (m GoogleV1Message) ProtoMessage()  {}

var _ googlev1.Message = &GoogleV1Message{}

type GoogleV2Message struct{}

func (g GoogleV2Message) ProtoReflect() protoreflect.Message { return nil }

var _ googlev2.Message = &GoogleV2Message{}

func TestDeduceMsgType(t *testing.T) {
	tt := []struct {
		msgType MessageType
		msg     interface{}
		prepare func()
	}{
		{
			msgType: MessageTypeGogo,
			msg:     &GogoMessage{},
			prepare: func() {
				gogo.RegisterType(&GogoMessage{}, "test_message")
			},
		},
		{
			msgType: MessageTypeGoogleV1,
			msg:     &GoogleV1Message{},
		},
		{
			msgType: MessageTypeGoogle,
			msg:     &GoogleV2Message{},
		},
		{
			msgType: MessageTypeUnknown,
			msg:     struct{}{},
		},
	}

	for _, tc := range tt {
		if tc.prepare != nil {
			tc.prepare()
		}
		require.Equal(t,
			tc.msgType,
			deduceMsgType(tc.msg, reflect.TypeOf(tc.msg)),
		)
	}
}
