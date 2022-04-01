package main

import (
	"strings"
	"testing"
	"text/template"
	"time"
)

func TestBasicRender(t *testing.T) {
	tt, _ := loadTemplateFromString("This is a test", nil)
	got, err := renderTemplate(tt, nil)
	if err != nil {
		t.Errorf("Expected no error from Render(), got %v", err)
	}
	if got != "This is a test" {
		t.Errorf("Expected \"This is a test\", got %q", got)
	}
}

func TestRenderWithValue(t *testing.T) {
	now := time.Now().Format(time.RFC3339)
	expected := "The current time is " + now

	tt, _ := loadTemplateFromString(`The current time is {{.}}`, nil)
	got, err := renderTemplate(tt, now)
	if err != nil {
		t.Errorf("Expected no error from Render(), got %v", err)
	}
	if got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}
}

func TestRenderWithFuncMap(t *testing.T) {
	formatFn := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
	now := time.Now()
	expected := "The current time is " + now.Format(time.RFC3339)
	funcs := template.FuncMap{
		"formatTime": formatFn,
	}

	tt, _ := loadTemplateFromString(`The current time is {{ formatTime . }}`, funcs)

	got, err := renderTemplate(tt, now)
	if err != nil {
		t.Errorf("Expected no error from Render(), got %v", err)
	}
	if got != expected {
		t.Errorf("Expected %q, got %q", expected, got)
	}
}

func TestRenderWithNilTemplate(t *testing.T) {
	_, err := renderTemplate(nil, nil)
	if err == nil {
		t.Error("Expected an error from renderTemplate(), got <nil>")
	} else if !strings.Contains(err.Error(), "cannot render a nil template") {
		t.Errorf("Unexpected error from Render(): %v", err)
	}
}

func TestLoadEmptyTemplate(t *testing.T) {
	_, err := loadTemplateFromString("", nil)
	if err == nil {
		t.Errorf("Expected an error from loadTemplateFromString(), got <nil>")
	} else if !strings.Contains(err.Error(), "cannot load an empty template") {
		t.Errorf("Unexpected error from loadTemplateFromString(): %v", err)
	}
}

func TestLoadInvalidTemplate(t *testing.T) {
	_, err := loadTemplateFromString(`This is a test {{ .`, nil)
	if err == nil {
		t.Errorf("Expected an error from loadTemplateFromString(), got <nil>")
	} else if !strings.Contains(err.Error(), "parse error in template") {
		t.Errorf("Unexpected error from loadTemplateFromString(): %v", err)
	}
}
