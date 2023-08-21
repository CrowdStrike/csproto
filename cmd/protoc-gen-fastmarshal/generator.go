package main

import (
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/compiler/protogen"
)

// generate ...
func generate(plugin *protogen.Plugin, req generateRequest) error {
	if req.Mode == outputModeSingleFile {
		return generateSingle(plugin, req)
	}
	return generatePerMessage(plugin, req)
}

func generateSingle(plugin *protogen.Plugin, req generateRequest) error {
	type genArgsSingle struct {
		Now                time.Time
		Pwd                string
		ProtoDesc          *protogen.File
		APIVersion         string
		SpecialNames       specialNames
		EnableUnsafeDecode bool
	}
	args := genArgsSingle{
		Now:                time.Now().UTC(),
		Pwd:                func() string { p, _ := os.Getwd(); return p }(),
		ProtoDesc:          req.ProtoDesc,
		APIVersion:         req.APIVersion,
		SpecialNames:       req.SpecialNames,
		EnableUnsafeDecode: req.EnableUnsafeDecode,
	}

	var (
		name, content string
		err           error
	)
	funcs := codeGenFunctions(req.ProtoDesc, req.SpecialNames, plugin)
	for k, v := range req.Funcs {
		funcs[k] = v
	}
	nt, err := loadTemplateFromString(req.NameTemplate, funcs)
	if err != nil {
		return fmt.Errorf("unable to parse output file name template: %w", err)
	}
	name, err = renderTemplate(nt, args)
	if err != nil {
		return fmt.Errorf("unable to generate output file name from name template: %w", err)
	}
	ct, err := loadTemplateFromEmbedded(funcs)
	if err != nil {
		return fmt.Errorf("unable to load embedded content templates: %w", err)
	}
	content, err = renderNamedTemplate(ct, "SingleFile", args)
	if err != nil {
		return fmt.Errorf("unable to generate output from content template: %w", err)
	}

	res := plugin.NewGeneratedFile(name, req.ProtoDesc.GoImportPath)
	if _, err = res.Write([]byte(content)); err != nil {
		return fmt.Errorf("error while writing output file: %w", err)
	}
	return nil
}

func generatePerMessage(plugin *protogen.Plugin, req generateRequest) error {
	type genArgsPerFile struct {
		Now                time.Time
		Pwd                string
		ProtoDesc          *protogen.File
		Message            *protogen.Message
		APIVersion         string
		SpecialNames       specialNames
		EnableUnsafeDecode bool
	}

	funcs := codeGenFunctions(req.ProtoDesc, req.SpecialNames, plugin)
	for k, v := range req.Funcs {
		funcs[k] = v
	}

	var (
		now    = time.Now().UTC()
		pwd, _ = os.Getwd()
	)

	tt, err := loadTemplateFromEmbedded(funcs)
	if err != nil {
		return fmt.Errorf("unable to load embedded content templates: %w", err)
	}
	for _, msg := range allMessages(req.ProtoDesc)() {
		args := genArgsPerFile{
			Now:                now,
			Pwd:                pwd,
			ProtoDesc:          req.ProtoDesc,
			Message:            msg,
			APIVersion:         req.APIVersion,
			SpecialNames:       req.SpecialNames,
			EnableUnsafeDecode: req.EnableUnsafeDecode,
		}
		content, err := renderNamedTemplate(tt, "PerMessage", args)
		if err != nil {
			return fmt.Errorf("error executing content template for message %s: %w", msg.Desc.FullName(), err)
		}

		nt, err := loadTemplateFromString(req.NameTemplate, funcs)
		if err != nil {
			return fmt.Errorf("error parsing file name template for message %s: %w", msg.Desc.FullName(), err)
		}

		fname, err := renderTemplate(nt, args)
		if err != nil {
			return fmt.Errorf("error executing file name template for message %s: %w", msg.Desc.FullName(), err)
		}

		result := plugin.NewGeneratedFile(fname, req.ProtoDesc.GoImportPath)
		if _, err = result.Write([]byte(content)); err != nil {
			return fmt.Errorf("error writing generated content for message %s to %q: %w", msg.Desc.FullName(), fname, err)
		}
	}

	return nil
}
