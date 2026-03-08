package main

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"

	"github.com/CrowdStrike/csproto"
)

func Test_doGenerate_Empty(t *testing.T) {
	flags := flag.NewFlagSet("", flag.PanicOnError)
	pluginOpts := protogen.Options{ParamFunc: flags.Set}

	plugin, err := pluginOpts.New(&pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{"empty.proto"},
		ProtoFile: []*descriptorpb.FileDescriptorProto{
			{
				Name:    csproto.String("empty.proto"),
				Package: csproto.String("crowdstrike.csproto.test"),
				Syntax:  csproto.String("proto3"),
				Options: &descriptorpb.FileOptions{
					GoPackage: csproto.String("github.com/CrowdStrike/csproto/testpb"),
				},
			},
		},
	})
	require.NoError(t, err)

	runPlugin := doGenerate(&options{
		specialNames: make(specialNames),
	})

	err = runPlugin(plugin)
	require.NoError(t, err)

	resp := plugin.Response()
	require.Empty(t, resp.File)
}
