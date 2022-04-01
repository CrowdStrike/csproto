package main

import (
	"bytes"
	"fmt"
	"text/template"
)

func loadTemplateFromString(s string, funcs template.FuncMap) (*template.Template, error) {
	if s == "" {
		return nil, fmt.Errorf("cannot load an empty template")
	}
	var err error
	t := template.New("csproto.template.render")
	if len(funcs) > 0 {
		t = t.Funcs(funcs)
	}
	t, err = t.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse error in template: %w", err)
	}

	return t, nil
}

func loadTemplateFromEmbedded(funcs template.FuncMap) (*template.Template, error) {
	var err error
	t := template.New("csproto.template.render")
	if len(funcs) > 0 {
		t = t.Funcs(funcs)
	}
	t, err = t.ParseFS(fastmarshalTemplates, "templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse error in template: %w", err)
	}

	return t, nil
}

// renderTemplate reads a Go text template from r then compiles and executes it, attaching funcs and passing in v,
// then returns the rendered text or an error.
func renderTemplate(t *template.Template, v interface{}) (string, error) {
	if t == nil {
		return "", fmt.Errorf("cannot render a nil template")
	}
	var buf bytes.Buffer
	err := t.Execute(&buf, v)
	if err != nil {
		return "", fmt.Errorf("unable to render template: %w", err)
	}
	return buf.String(), nil
}

// renderNamedTemplate executes a Go text template by name from those defined in templates/*.tmpl,
// attaching funcs and passing in v.
func renderNamedTemplate(t *template.Template, name string, v interface{}) (string, error) {
	if t == nil {
		return "", fmt.Errorf("cannot render a nil template")
	}
	if name == "" {
		return "", fmt.Errorf("template name must be specified")
	}
	var buf bytes.Buffer
	err := t.ExecuteTemplate(&buf, name, v)
	if err != nil {
		return "", fmt.Errorf("unable to render template: %w", err)
	}
	return buf.String(), nil
}
