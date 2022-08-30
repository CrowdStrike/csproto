# `csproto` - CrowdStrike's Protocol Buffers library

[![GoDoc](https://pkg.go.dev/badge/github.com/CrowdStrike/csproto.svg)](https://pkg.go.dev/github.com/CrowdStrike/csproto)

`csproto` is a Go module that provides a library for working with Protocol Buffers messages along with
a `protoc` plug-in for generating optimized marshaling and unmarshaling code for those messages.

Like many other companies, CrowdStrike extensively uses Protocol Buffers as an efficient wire format
for communicating between disparate processes and services.  Protocol Buffers' [compatibility guarantees](https://developers.google.com/protocol-buffers/docs/overview#updating)
and smaller, more efficient binary encoding made it a natural fit for the problems we needed to solve.

As our data volume continued to grow, CrowdStrike started to run into performance limitations in
[Google's Protobuf library](https://github.com/golang/protobuf) and transitioned to using [Gogo Protobuf](https://github.com/gogo/protobuf)
in an attempt to overcome the issues.  This adjustment proved successful and "Use Gogo Protobuf" became
the de facto guidance within our development teams.

Fast forward to 2020 when the maintainers of that library announced that they are [looking for people to take over](https://github.com/gogo/protobuf/issues/691).
Unfortunately, this also coincided with Google releasing [V2](https://blog.golang.org/protobuf-apiv2)
of their Protobuf API.  As new and/or improved functionality was introduced in Google's library, the
lack of active maintenance on Gogo inevitably led to incompatibilities.

This created a problem for CrowdStrike.  We needed to update our system to no longer depend on Gogo
Protobuf but we had **a lot** of direct dependencies on that code spread throughout our codebase.
The solution we arrived at is this library.  It provides the "core" pieces of the Protocol
Buffers API as used by consumers without having those consumers _directly_ depend on any particular
runtime implementation.

If you want to dive right in, there's a handy [migration guide](docs/migration_guide.md).  Otherwise, keep reading for all of the technical details.

_Disclaimer: `csproto` is an open source project, not a CrowdStrike product. As such, it carries no
formal support, expressed or implied.  The project is licensed under the MIT open source license._

## Supporting Types Across Runtime Implementations

As part of their V2 API, Google also introduced significant changes to the `protoc` code generation plug-in,
`protoc-gen-go`.  One effect of this change was that code generated using the new plug-in uses the new
API internally.  An unfortunate side effect is that those types are no longer compatible with Gogo's API.

One technical limitation of Protocol Buffers is that deserializing a message requires knowledge of the
actual message type because the encoded field values only contain the integer field tag.  Due to this
limitation, both Google and Gogo use reflection to read the struct tags on the generated Go types and
to dynamically assign field values when unmarshaling Protobuf messages.

This dependence on reflection has created a scenario where passing a type generated by the new plug-in
to Gogo's implementation of `csproto.Unmarshal()` results in failures.  Specifically, there are several
new fields in the generated code and the reflection-based logic in Gogo's library doesn't know how to
treat them.  Additionally, several fields that are used by the V1 API, and consequently Gogo's library,
are no longer generated.

### A Minimal Protocol Buffers API

After a bit of digging, we came up with what we consider the smallest API necessary to support reading
and writing Protocol Buffers messages that does not expose any dependence on the runtime implementations.

- `Size(msg interface{}) int`
  - Calculate the size, in bytes, required to hold the binary representation of `msg`
- `Marshal(msg interface{}) ([]byte, error)`
  - Convert the contents of `msg` to the binary representation and return it
- `Unmarshal(p []byte, msg interface{}) error`
  - Populate `msg` with the contents of the binary message in `p`
- `HasExtension(msg interface{}, ext interface{}) bool`
  - Determine if `msg` contains a proto2 extension field
- `ClearExtension(msg interface{}, ext interface{})`
  - Clears a proto2 extension field from `msg`
- `GetExtension(msg interface{}, ext interface{}) (interface{}, error)`
  - Return the value of a proto2 extension field from `msg`
- `SetExtension(msg interface{}, ext interface{}, val interface{}) error`
  - Assign the value of a proto2 extension field on `msg`

There isn't any common interface shared between Google's two runtimes and Gogo's runtime so our library
had to use the empty interface for all message and extension definition parameters.

With this minimal API, services and libraries are able to create and consume Protobuf-encoded messages
without being tightly coupled to any specific runtime.  Being able to do this was essential for CrowdStrike
because it is simply impossible to update everything at once to change which runtime library is in use.
Instead, we gradually updated all of our libraries and services to use this new runtime-independent API
so that each of our development teams is able to change out their runtime and code generation dependencies
independently.

### Don't Recreate Everything

Our intent is not to fully recreate the Protocol Buffers runtime.  Instead, `csproto` is built to
determine which existing runtime is the "correct" one for a given message and to delegate to that implementation.

We take advantage of the fact that the Go types can't change at runtime to minimize the impact of this
indirection.  The underlying type of the `msg` parameter is inspected to determine which of the 3
supported runtimes (Google V1, Gogo, and Google V2) is correct and we store that value in a lookup
dictionary so that any given type only has to be inspected once.

Even with this optimization, calling `reflect.TypeOf()` on the message and performing the lookup has
a cost, over 8% in some scenarios!  At CrowdStrike's volume even that difference can add up to a
non-trivial impact across the system so we needed to find a way to at least break even but, ideally,
to better the performance.

The benchmarks below for proto2 marshaling were generated on a 2019 MacBook Pro:

```bash
$ go test -run='^$' -bench=. -benchmem
goos: darwin
goarch: amd64
pkg: github.com/CrowdStrike/csproto/example/proto2
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkEncodeGogo-12                   1741834               667.4 ns/op           216 B/op          4 allocs/op
BenchmarkCustomEncodeGogo-12             1785268               669.2 ns/op           216 B/op          4 allocs/op
BenchmarkEncodeGoogleV1-12               1326734               921.7 ns/op           176 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV1-12         1315390               933.5 ns/op           176 B/op          1 allocs/op
BenchmarkEncodeGoogleV2-12               1329092               906.9 ns/op           176 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV2-12         1306638               923.3 ns/op           176 B/op          1 allocs/op
```

And for proto3:

```bash
$ go test -run='^$' -bench=. -benchmem
goos: darwin
goarch: amd64
pkg: github.com/CrowdStrike/csproto/example/proto3
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkEncodeGogo-12                   3008721               394.1 ns/op            88 B/op          2 allocs/op
BenchmarkCustomEncodeGogo-12             2900726               400.1 ns/op            88 B/op          2 allocs/op
BenchmarkEncodeGoogleV1-12               3109386               388.2 ns/op            80 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV1-12         2990907               392.8 ns/op            80 B/op          1 allocs/op
BenchmarkEncodeGoogleV2-12               3290887               367.7 ns/op            80 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV2-12         3003828               398.3 ns/op            80 B/op          1 allocs/op
```

The table below shows the approximate cost of the indirection across the various combinations of
Protobuf runtimes:

Cost      | proto2  | proto3
--------- | ------- | ------
Gogo      | +0.27%  | +1.52%
Google V1 | +1.28%  | +1.18%
Google V2 | +1.81%  | +8.32%

## Optimized Protobuf Marshaling and Unmarshaling

The marshaling and unmarshaling implemented by both Google and Gogo necessarily relies on runtime reflection.
Both implementations dynamically query the set of fields on the message type and read the associated
Protobuf struct tags. This information is then used to match up the field tag and wire type in the
encoded data to the corresponding field on the message and to assign the field values.  This solution
is generic and can be applied to any/all messages without any changes to the implementation but it is
necessary slower because it has to inspect each message much more deeply.

Another common source of performance bottlenecks is repeated small allocations.  It is, in most cases,
far more efficient to allocate one buffer large enough to hold all of the data you need than to incrementally
allocate many smaller buffers.

Before moving on, credit must be given to the Vitess team for their [`vtprotobuf` project](https://github.com/planetscale/vtprotobuf)
which they covered in [this blog from June of 2021](https://vitess.io/blog/2021-06-03-a-new-protobuf-generator-for-go/).
That project already implements these strategies and more, only with some constraints that didn't work for us.
Specifically, `vtprotobuf` is only compatible with things that are already using Google's V2 API.  Given
that the inception of this project for CrowdStrike was due to our dependency on Gogo Protobuf we weren't
able to make use of their work.  We also make significant usage of proto2 extensions, which may or may not
be supported by the Vitess tooling.

### Protocol Buffers Binary Codec

The first step to improving Protobuf serialization is to implement a binary encoder and decoder that
avoids the issues noted in the last section.  Additionally, the Protocol Buffer
[encoding spec](https://developers.google.com/protocol-buffers/docs/encoding) has a much smaller surface
area than the set of all valid Protobuf messages.

#### Encoder

The [`Encoder`](encoder.go) type wraps a pre-allocated byte slice and sequentially writes encoded
field values to it. It is up to the caller to ensure that the provided buffer is large enough to hold
the full encoded value.  As each encoded field is prefixed by the integer field tag and Protobuf wire
type, `Encoder`'s API is provided as a set of `EncodeXxx(tag int, val T)` methods, one for each supported
type of value.

This snippet encodes a boolean `true` value with a field tag of 1:

```go
// Protobuf binary encoding will require 2 bytes, 1 for the tag/wire type and 1 for the value
buf := make([]byte, 2)
enc := csproto.NewEncoder(buf)
enc.EncodeBool(1, true)
// buf now contains {0x8, 0x1}
```

Encoding a full message is similar, but using [`csproto.Size()`](sizeof.go) to calculate the required buffer size.

```go
msg := SomeMessage{
    Name: csproto.String("example"),
    Value: csproto.Int32(42),
    // assign additional fields
}
siz := csproto.Size(msg)
buf := make([]byte, siz)
enc := csproto.NewEncoder(buf)
// encode each field sequentially
enc.EncodeString(1, msg.Name)
enc.EncodeInt32(2, msg.Value)
// ...
```

#### Decoder

Like `Encoder`, the [`Decoder`](decoder.go) type wraps a byte slice and sequentially reads field
values from it.  The Protobuf encoding does not require fields to be in tag order, or present at all
for that matter, so decoding a message requires a `for` loop combined with a `switch` statement.

```go
func decodeExample(p []byte) (SomeMessage, error) {
    var (
        msg SomeMessage
        s string
        i32 int32
    )
    dec := csproto.NewDecoder(p)
    for dec.More() {
        tag, wireType, err := dec.DecodeTag()
        if err != nil {
            return SomeMessage{}, err
        }
        switch tag {
        case 1: // Name
            if wireType != csproto.WireTypeLengthDelimited {
                return SomeMessage{}, fmt.Errorf("invalid wire type %s, expected %s", wireType, csproto.WireTypeLengthDelimited)
            }
            s, err = dec.DecodeString()
            if err != nil {
                return SomeMessage{}, fmt.Errorf("unable to decode string: %w", err)
            }
            msg.Name = csproto.String(s)
        case 2: // Value
            if wireType != csproto.WireTypeVarint {
                return SomeMessage{}, fmt.Errorf("invalid wire type %s, expected %s", wireType, csproto.WireTypeVarint)
            }
            i32, err = dec.DecodeInt32()
            if err != nil {
                return SomeMessage{}, fmt.Errorf("unable to decode int32: %w", err)
            }
            msg.Value = csproto.Int32(i32)
        default: // unknown/unrecognized field, skip it
            _, _ = dec.Skip(tag, wireType)
        }
    }
}
```

Notes:

- The cases in the `switch` statement use `csproto.String()` and `csproto.Int32()` to grab pointers to
  copies of the decoded values.
- The example above simply throws away unknown fields which you shouldn't do in practice.

##### Safe vs Fast

By default, `Decoder.DecodeString()` will make a full copy of the decoded string.  This is the safest,
most stable practice but it does come with a small cost in both time and allocations.  For scenarios
where maximum performance is more desirable, `Decoder` supports a "fast" mode that uses `unsafe` to
return the bytes of wrapped buffer directly, saving the type conversion and allocation to create a
new `string` value.

```go
...
dec := csproto.NewDecoder(p)
dec.SetMode(proto.DecoderModeFast)
...
s, err := dec.DecodeString()
...
```

Representative benchmarks from a 2019 MacBook Pro

```bash
...> go test -run='^$' -bench=DecodeString -benchmem ./proto
goos: darwin
goarch: amd64
pkg: github.com/CrowdStrike/csproto
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkSafeDecodeString-12            37183212                27.33 ns/op           16 B/op          1 allocs/op
BenchmarkFastDecodeString-12            127437440                9.211 ns/op           0 B/op          0 allocs/op
```

The trade off for the increased performance is that the behavior is undefined if the wrapped buffer
is modified after decoding the field values from it.

### Opting In

Now that we have a custom, optimized codec available, we need a way to seamlessly integrate it into
the developer workflow.  We do that by defining several new interfaces which our API functions will
look for when marshaling or unmarshaling messages.

We define 4 single-method interfaces as integration points:

- `csproto.Sizer`
  - `Size() int`: calculates the size, in bytes, needed to hold the encoded contents of the message
    - `csproto.Size()` will call this method if the message satisfies the interface
- `csproto.Marshaler`
  - `Marshal() ([]byte, error)`: returns the binary encoding of the message
    - `csproto.Marshal()` will call this method if the message satisfies the interface
- `csproto.MarshalerTo`
  - `MarshalTo([]byte) error`: encodes the message into the provided buffer
    - `csproto.Marshal()` will call this method, after allocating a sufficiently sized buffer, if the messaage
      satisfies the interface
- `csproto.Unmarshaler`
  - `Unmarshal([]byte) error`: decodes the provided data into the message
    - `csproto.Unmarshal()` will call this method if the message satisfies the interface

With this in place developers have all of the parts needed to create a fully optimized implementation
of Protocol Buffer marshaling and unmarshaling.  We can make things even better, though, by capitalizing
on the fact that the Protobuf IDL that developers have already written has all of the information we
need to generate those optimized implementations.

### The `protoc` plug-in

The final piece of the puzzle is `protoc-gen-fastmarshal`, a `protoc` compiler plug-in that reads the
Protobuf file descriptor and emits implementations of the `Size`, `Marshal`, `MarshalTo`,
and `Unmarshal` methods for each message defined in the `.proto` file.

Given this example message

```protobuf
message Example {
  string name   = 1;
  int32  result = 2;
}
```

the generated code would be roughly as follows

```go
// Size returns the size, in bytes, required to store the contents of m in Protocol Buffers
// binary format.
func (m *Example) Size() int {
  if m == nil {
    return 0
  }
  var (
    sz, l int
  )
  // Name
  if m.Name != nil {
    // key + len + bytes
    l = len(*m.Name)
    sz += csproto.SizeOfVarint(uint64(1)) + csproto.SizeOfVarint(uint64(l)) + l
  }
  // Result
  if m.Result != nil {
    // key + varint
    sz += csproto.SizeOfVarint(uint64(2)) + csproto.SizeOfVarint(uint64(*m.Result))
  }
  // unknown/unrecognized fields
  sz += len(m.unknownFields)
  return sz
}
// Marshal allocates a buffer, writes the contents of m to it using Protocol Buffers binary
// format, then returns the the buffer.
func (m *Example) Marshal() ([]byte, error) {
  sz := m.Size()
  buf := make([]byte, sz)
  err := m.MarshalTo(buf)
  return buf, err
}
// MarshalTo writes the contents of m into dest using Protocol Buffers binary format.
func (m *Example) MarshalTo(dest []byte) error {
  var (
    buf []byte
    err error
  )
  enc := csproto.NewEncoder(dest)
  if m.Name != nil {
    enc.EncodeString(1, *m.Name)
  }
  if m.Result != nil {
    enc.EncodeInt32(2, *m.Result)
  }
  if len(m.unknownFields) > 0 {
    enc.EncodeRaw(m.unknownFields)
  }
  return nil
}
// Unmarshal decodes the Protocol Buffers binary format message in p and populates m with the
// result.
func (m *Example) Unmarshal(p []byte) error {
  if len(p) == 0 {
    return fmt.Errorf("cannot unmarshal from empty buffer")
  }
  var (
    tag int
    wt  csproto.WireType
    err error
  )
  dec := pbtools.NewDecoder(p)
  for dec.More() {
    tag, wt, err = dec.DecodeTag()
    if err != nil {
      return err
    }
    switch tag {
    case 1: // Name
      if wt != csproto.WireTypeLengthDelimited {
        return fmt.Errorf("invalid message data, expected wire type 2 for tag 1, got %v", wt)
      }
      if v, err := dec.DecodeString();  err != nil {
        return fmt.Errorf("unable to decode string value for tag 1: %w", err)
      } else {
        m.Name = csproto.String(v)
      }
    case 2: // Result
      if wt != csproto.WireTypeVarint {
        return fmt.Errorf("invalid message data, expected wire type 0 for tag 2, got %v", wt)
      }
      if v, err := dec.DecodeInt32(); err != nil {
        return fmt.Errorf("unable to decode int32 value for tag 2: %w", err)
      } else {
        m.Result = csproto.Int32(v)
      }
    default: // unrecognized/unknown field
      if skipped, err := dec.Skip(tag, wt); err != nil {
        return fmt.Errorf("invalid operation skipping tag %v: %w", tag, err)
      } else {
        m.unknownFields = append(m.unknownFields, skipped)
      }
    }
  }
  return nil
}
```

### Final Benchmarks

After invoking `protoc-gen-fastmarshal`, the final benchmarks for our examples are:

```bash
$ go test -run='^$' -bench=. -benchmem ./proto2 ./proto3
goos: darwin
goarch: amd64
pkg: github.com/CrowdStrike/csproto/example/proto2
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkEncodeGogo-12                   1932699               597.6 ns/op           352 B/op          2 allocs/op
BenchmarkCustomEncodeGogo-12             2458599               482.3 ns/op           176 B/op          1 allocs/op
BenchmarkDecodeGogo-12                    622585              1887 ns/op            1376 B/op         34 allocs/op
BenchmarkCustomDecodeGogo-12              798523              1390 ns/op            1144 B/op         27 allocs/op
BenchmarkEncodeGoogleV1-12               1298185               925.5 ns/op           176 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV1-12         2701975               432.4 ns/op           176 B/op          1 allocs/op
BenchmarkDecodeGoogleV1-12                616106              1662 ns/op            1176 B/op         28 allocs/op
BenchmarkCustomDecodeGoogleV1-12          776244              1471 ns/op            1160 B/op         26 allocs/op
BenchmarkEncodeGoogleV2-12               1331971               911.3 ns/op           176 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV2-12         2817786               426.1 ns/op           176 B/op          1 allocs/op
BenchmarkDecodeGoogleV2-12                671048              1739 ns/op            1176 B/op         28 allocs/op
BenchmarkCustomDecodeGoogleV2-12          755186              1530 ns/op            1160 B/op         26 allocs/op
PASS
ok      github.com/CrowdStrike/csproto/example/proto2   12.247s

goos: darwin
goarch: amd64
pkg: github.com/CrowdStrike/csproto/example/proto3
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkEncodeGogo-12                   3479755               341.0 ns/op           208 B/op          3 allocs/op
BenchmarkCustomEncodeGogo-12             4824855               248.1 ns/op           112 B/op          2 allocs/op
BenchmarkDecodeGogo-12                   1328734               909.9 ns/op           424 B/op         16 allocs/op
BenchmarkCustomDecodeGogo-12             1604020               753.5 ns/op           408 B/op         15 allocs/op
BenchmarkEncodeGoogleV1-12               2599558               450.6 ns/op            96 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV1-12         3452514               348.4 ns/op           112 B/op          2 allocs/op
BenchmarkDecodeGoogleV1-12                962179              1076 ns/op             440 B/op         16 allocs/op
BenchmarkCustomDecodeGoogleV1-12         1337054               904.2 ns/op           424 B/op         15 allocs/op
BenchmarkEncodeGoogleV2-12               2741904               433.4 ns/op            96 B/op          1 allocs/op
BenchmarkCustomEncodeGoogleV2-12         3337425               356.1 ns/op           112 B/op          2 allocs/op
BenchmarkDecodeGoogleV2-12               1000000              1077 ns/op             440 B/op         16 allocs/op
BenchmarkCustomDecodeGoogleV2-12         1327365               913.4 ns/op           424 B/op         15 allocs/op
PASS
ok      github.com/CrowdStrike/csproto/example/proto3   9.186s
```

As you can see in the table below, the optimized code is faster across the board.

Cost      | proto2 (encode)  | proto3 (encode) | proto2 (decode) | proto3 (decode)
--------- | ---------------- | --------------- | --------------- | ---------------
Gogo      | -19.3%           | -27.2%          | -26.3%          | -17.2%
Google V1 | -53.3%           | -22.7%          | -11.5%          | -16.0%
Google V2 | -53.3%           | -17.8%          | -12.0%          | -15.2%

### A Warning About `proto2` Extension Fields

Unfortunately, the news is not all good.  This library is limited to the public APIs of the three underlying runtimes when working with `proto2` extension fields and those APIs take advantage of unexported features to gain efficiency.  Since they are unexported, those efficiency gains are unavailable to the code in `csproto` and the code generated by `protoc-gen-fastmarshal` that calls it.

One significant difference is in `Unmarshal()`.  All three runtimes have internal code that delays decoding the bytes of `proto2` extension fields until `GetExtension()` is called.  Since `csproto` does not have access to this code, the unmarshaling code generated by `protoc-gen-fastmarshal` has to actually decode the extension field then explicitly call `SetExtension()` with the result.  In some cases we've seen this be as much as 30% slower than calling the underlying `proto.Unmarshal()` directly.  You can see this in action by removing the calls to `GetExtension()` from [the proto2 Gogo benchmarks](./example/proto2/gogo_benchmarks_test.go) and observing the change in the resulting measurements.

Because of these issues, we advise that projects which rely heavily on `proto2` extension fields **SHOULD NOT** use `protoc-gen-fastmarshal` to generate custom marshal/unmarshal code.

## gRPC

To use with gRPC you will need to register `csproto` as the encoder.
**NOTE:** If messages do not implement `Marshaler` or `Unmarshaler` then an error will be returned.
An example is below.

For more information, see [the gRPC documentation](https://github.com/grpc/grpc-go/blob/master/Documentation/encoding.md).

```go
import (
  "github.com/CrowdStrike/csproto"
  "google.golang.org/grpc/encoding"
  _ "google.golang.org/grpc/encoding/proto"
)

func init() {
  encoding.RegisterCodec(csproto.GrpcCodec{})
}
```
