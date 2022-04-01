package csproto

import (
	"fmt"

	gogo "github.com/gogo/protobuf/proto"
	google "github.com/golang/protobuf/proto" //nolint: staticcheck // we're using this deprecated package intentionally
	googlev2 "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// HasExtension returns true if msg contains the specified proto2 extension field, delegating to the
// appropriate underlying Protobuf API based on the concrete type of msg.
func HasExtension(msg interface{}, ext interface{}) bool {
	switch MsgType(msg) {
	case MessageTypeGoogleV1:
		ed, ok := ext.(*google.ExtensionDesc)
		if !ok {
			return false
		}
		return google.HasExtension(msg.(google.Message), ed)
	case MessageTypeGoogle:
		et, ok := ext.(protoreflect.ExtensionType)
		if !ok {
			return false
		}
		return googlev2.HasExtension(msg.(googlev2.Message), et)
	case MessageTypeGogo:
		ed, ok := ext.(*gogo.ExtensionDesc)
		if !ok {
			return false
		}
		return gogo.HasExtension(msg.(gogo.Message), ed)
	default:
		return false
	}
}

// GetExtension returns a proto2 extension field from msg, delegating to the appropriate underlying
// Protobuf API based on the concrete type of msg.
func GetExtension(msg interface{}, ext interface{}) (interface{}, error) {
	switch MsgType(msg) {
	case MessageTypeGoogleV1:
		ed, ok := ext.(*google.ExtensionDesc)
		if !ok {
			return nil, fmt.Errorf("invalid extension description type %T", ext)
		}
		return google.GetExtension(msg.(google.Message), ed)
	case MessageTypeGoogle:
		et, ok := ext.(protoreflect.ExtensionType)
		if !ok {
			return nil, fmt.Errorf("invalid extension type %T", ext)
		}
		return googlev2.GetExtension(msg.(googlev2.Message), et), nil
	case MessageTypeGogo:
		ed, ok := ext.(*gogo.ExtensionDesc)
		if !ok {
			return nil, fmt.Errorf("invalid extension description type %T", ext)
		}
		return gogo.GetExtension(msg.(google.Message), ed)
	default:
		return nil, fmt.Errorf("unsupported message type %T", ext)
	}
}

// SetExtension sets a proto2 extension field in msg to the provided value, delegating to the
// appropriate underlying Protobuf API based on the concrete type of msg.
func SetExtension(msg interface{}, ext interface{}, val interface{}) error {
	switch MsgType(msg) {
	case MessageTypeGoogleV1:
		ed, ok := ext.(*google.ExtensionDesc)
		if !ok {
			return fmt.Errorf("invalid extension description type %T", ext)
		}
		return google.SetExtension(msg.(google.Message), ed, val)
	case MessageTypeGoogle:
		et, ok := ext.(protoreflect.ExtensionType)
		if !ok {
			return fmt.Errorf("invalid extension type %T", ext)
		}
		googlev2.SetExtension(msg.(googlev2.Message), et, val)
		return nil
	case MessageTypeGogo:
		ed, ok := ext.(*gogo.ExtensionDesc)
		if !ok {
			return fmt.Errorf("invalid extension description type %T", ext)
		}
		return gogo.SetExtension(msg.(google.Message), ed, val)
	default:
		return fmt.Errorf("unsupported message type %T", ext)
	}
}
