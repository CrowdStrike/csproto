# Migration Guide

This document outlines the process of migrating existing code that is referencing `github.com/gogo/protobuf` or `github.com/golang/protobuf` to instead use `github.com/CrowdStrike/csproto`, and thereby become _mostly_ agnostic of the underlying Protobuf runtime.  Because `csproto` is designed to, as mush as possible, be a drop-in replacement the migration steps are minimal.

## Decoupling Code

The first step is unsurprisingly to swap out all references to the 6 "core" Protobuf APIs for the implementations provided by `csproto`.  Because the functions provided by `csproto` are intentionally compatible with the existing call sites, this becomes a simple search-and-replace.

1. Find all files that import `github.com/gogo/protobuf/proto` and/or `github.com/golang/protobuf/proto` using the tool of your choice
2. For each file that isn't generated code:
   1. Add an import for `github.com/CrowdStrike/csproto`
   2. Update all calls to the Gogo/Google functions to their `csproto` equivalents per the table below
   3. Remove the import(s) for `github.com/gogo/protobuf/proto` and/or `github.com/golang/protobuf/proto`

| Existing call                                                           | Equivalent `csproto` call                                                 |
|-------------------------------------------------------------------------|-----------------------------------------------------|
| `sz := proto.Size(msg)`                                                 | `sz := csproto.Size(msg)`                                                    |
| `data, err := proto.Marshal(msg)`                                       | `data, err := csproto.Marshal(msg)`                                               |
| `err := proto.Unmarshal(data, &msg)`                                    | `err := csproto.Unmarshal(data, &msg)`                                        |
| `exists := proto.HasExtension(msg, yourpb.E_SomeEvent_YourExtension)`   | `exists := csproto.HasExtension(msg, yourpb.E_SomeEvent_YourExtension)` |
| `ext, err := proto.GetExtension(msg, yourpb.E_SomeEvent_YourExtension)` | `ext, err := csproto.GetExtension(msg, yourpb.E_SomeEvent_YourExtension)` |
| `err := proto.SetExtension(msg, yourpb.E_SomeEvent_YourExtension, ext)` | `err := csproto.SetExtension(msg, yourpb.E_SomeEvent_YourExtension, ext)`        |

### So you're also using `jsonpb`

Unfortunately, the different APIs for writing a Protobuf message to JSON between Google V1/Gogo (in the `jsonpb` packages) and Google V2 (in `protojson`) means that there isn't a single function that covers all three underlying runtimes.  Instead, we provide an adapter API that supports the commonality between the 3 and, for general interoperability, satisfies the [`json.Marshaler`](https://pkg.go.dev/encoding/json#Marshaler) interface.

Using `jsonpb`:

```go
var data bytes.Buffer
m := jsonpb.Marshaler{
   Indent:       "  ",
   EnumsAsInts:  true,
   EmitDefaults: true,
}
err := m.Marshal(&data, msg)
```

Using `csproto`:

```go
jsonOpts := []csproto.JSONOption{
   csproto.JSONIndent("  "),
   csproto.JSONUseEnumNumbers(true),
   csproto.JSONIncludeZeroValues(true),
}
// create an adapter and call MarshalJSON directly
m := csproto.JSONMarshaler(msg, jsonOpts...)
data, err := m.MarshalJSON()
// or call json.Marshal()
data, err := json.Marshal(csproto.JSONMarshaler(msg, jsonOpts...))
```

If you need more control that this adapter provides, you will need to use the V2 [`protojson`](https://pkg.go.dev/google.golang.org/protobuf/encoding/protojson) API directly.

### Or you're using `proto.Buffer`

The `proto.Buffer` type implements a wrapper around a buffer and provides methods for encoding and decoding individual message fields.  We took a slightly different tack with `csproto`.  You can convert your code to use `csproto.Encoder` or `csproto.Decoder` to encode or decode values, respectively.  In some cases, the `csproto` API is even more user-friendly.

Using `gogo/protobuf`:

```go
buf := proto.NewBuffer(data)
val, err := buf.DecodeVarint()
if err != nil {
   // handle failure
   return
}
tag, wireType := int(val)>>3, int(val & 0x7)
if tag != 1 {
   // handle unexpected tag
   return
}
if wireType != proto.WireBytes {
   // handle invalid field
   return
}
s, err := buf.DecodeStringBytes()
if err != nil {
   // handle decode error
   return
}
fmt.Println("tag:", tag, ", value:", s)
```

Using `csproto`:

```go
d := csproto.NewDecoder(data)
tag, wireType, err := d.DecodeTag()
switch {
case tag != 1:
   // handle unexpected tag
   return
case err != nil:
   // handle failure
   return
case wireType != csproto.WireTypeLengthDelimited:
   // handle invalid field:
   return
default:
}
s, err := d.DecodeString()
if err != nil {
   // handle decode error
   return
}
fmt.Println("tag:", tag, ", value:", s)
```

A similar translation can be done to replace `proto.Buffer` with `csproto.Encoder` for writing raw fields, with the caveat that `Encoder` requires that the caller allocates the destination buffer rather than holding its own internal buffer and growing it as needed.

## Updating Code Generation

Now that your non-generated code has been decoupled, the next step is to fix up the generated code.  Since the `csproto` library only provides shim APIs, you'll need to convert to using `protoc-gen-go` from the Protobuf V2 API in `google.golang.org/protobuf`.

```bash
> go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```

### Switching from Google V1

The command invocation for `protoc-gen-go` to generate `.pb.go` files is the same, so you're done.  Congratulations!

### Switching from Gogo Protobuf

If you are only using the baseline features of `protoc-gen-gogo`, then you _should_ only need to replace `--gogo_out` with `--go_out` in your `protoc` invocation.

```bash
# before
> protoc -I . --gogo_out=paths=source_relative:. yourapi.proto

# after
> protoc -I . --go_out=paths=source_relative:. yourapi.proto
```

Unfortunately, if you are currently using the more advanced code generation enabled by `protoc-gen-gogofast`, `protoc-gen-gogofaster`, or `protoc-gen-gogoslick` then you will lose functionality as the new `protoc-gen-go` plug-in does not provide the same features.

The specifics of updating your code to no longer depend on those extended features will vary from project to project.

### gRPC

With the new V2 API, `protoc-gen-go` no longer emits gRPC code so you will need to install and use the new `protoc-gen-go-grpc` plug-in.

```bash
> go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

And the invocation:

```bash
# before
> protoc -I . --go_out=paths=plugins=grpc:. yourapi.proto

# after
> protoc -I . --go_out=. --go-grpc_out=. yourapi.proto
```

#### Unimplemented gRPC Servers

The new `protoc-gen-go-grpc` plug-in also includes new functionality to aid with [future-proofing](https://pkg.go.dev/google.golang.org/grpc/cmd/protoc-gen-go-grpc#section-readme) gRPC server implementations.  By default, gRPC server implementations now can embed the generated `Unimplemented<ServiceName>Server` type to automatically "inherit" stub implementations of the gRPC service interface.  If you do not want this new behavior, you can opt out.

```bash
> protoc -I . --go_out=. --go-grpc_out=require_unimplemented_servers=false. yourapi.proto
```

It is, however, recommended that you do update your service implementations to embed the generated "unimplemented server" types.

### But I Still Want to Go FAST

As noted in [README.md](../README.md), inserting the shim functions provided by `csproto` does come with a small runtime cost.  Additionally, the performance of the Protobuf V2 API can, in some cases, be significantly slower than the equivalent code using Gogo Protobuf.

If you feel like this loss is more than your project can absorb, you can add `protoc-gen-fastmarshal` to your code generation steps to emit performant, reflection-free marshal and unmarshal code for your Protobuf message types.

```bash
> go install github.com/CrowdStrike/csproto/cmd/protoc-gen-fastmarshal@latest
```

The plug-in is invoked similarly to other `protoc` plug-ins and will output a `yourapi.fm.pb.go` file (or optionally a separate file for each message) that contains implementations of the four methods that the `csproto` shim functions look for when marshaling or unmarshaling messages.

```bash
# for a single file
> protoc [other options] --fastmarshal_out=paths=source_relative:. yourapi.proto

# for a file per message
> protoc [other options] --fastmarshal_out=paths=source_relative,filepermessage=true:. yourapi.proto
```

Refer to [`Makefile`](../Makefile) and the generated code in the [`github.com/CrowdStrike/csproto/example` module](../example/) for examples of the other available options and the resulting generated code.

#### gRPC Should Be Fast Too

To take full advantage of the more performant code generated by `protoc-gen-fastmarshal` for your gRPC services, you will want to register the gRPC codec provided by `csproto` with the gRPC runtime.

```go
import (
  "github.com/CrowdStrike/csproto"
  "google.golang.org/grpc/encoding"
  _ "google.golang.org/grpc/encoding/proto"
)
func main() {
   ...
   encoding.RegisterCodec(csproto.GrpcCodec{})
   ...
}
```

A warning, though.  `csproto.GrpcCodec{}` will fail if it sees a message that does not provide the custom marshal/unmarshal methods generated by `protoc-gen-fastmarshal`.
