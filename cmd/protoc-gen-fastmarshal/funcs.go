package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/huandu/xstrings"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	standardFuncs = template.FuncMap{
		// string calls .String() on v
		"string": func(v interface{}) string {
			switch tv := v.(type) {
			case fmt.Stringer:
				return tv.String()
			default:
				return fmt.Sprintf("%s", v)
			}
		},
		// json converts v to JSON by calling json.Marshal()
		// . if marshaling fails, the error text is returned instead
		"json": func(v interface{}) string {
			a, err := json.Marshal(v)
			if err != nil {
				return err.Error()
			}
			return string(a)
		},
		// prettyjson converts v to formatted JSON by calling json.MarshalIndent()
		// . if marshaling fails, the error text is returned instead
		"prettyjson": func(v interface{}) string {
			a, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return err.Error()
			}
			return string(a)
		},
		// splitTrimEmpty splits s on sep then returns the result, excluding empty items
		"splitTrimEmpty": func(sep string, s string) []string {
			tokens := strings.Split(s, sep)
			result := tokens[:0]
			for _, t := range tokens {
				if t != "" {
					result = append(result, t)
				}
			}
			return result
		},
		// first returns the first element of a, or "" if a is empty
		"first": func(a []string) string {
			if len(a) == 0 {
				return ""
			}
			return a[0]
		},
		// last returns the last element of a, or "" if a is empty
		"last": func(a []string) string {
			if len(a) == 0 {
				return ""
			}
			return a[len(a)-1]
		},
		// concat appends one or more strings onto the end of a
		"concat": func(a string, b ...string) string {
			return strings.Join(append([]string{a}, b...), "")
		},
		// join concatenates the strings in a using sep as the element separator
		"join": func(sep string, a ...string) string {
			return strings.Join(a, sep)
		},
		// upperFirst returns s with the first character converted to upper-case
		"upperFirst": func(s string) string {
			switch len(s) {
			case 0:
				return ""
			case 1:
				return strings.ToUpper(s)
			default:
				return strings.ToUpper(s[:1]) + s[1:]
			}
		},
		// lowerFirst returns s with the first character converted to lower-case
		"lowerFirst": func(s string) string {
			switch len(s) {
			case 0:
				return ""
			case 1:
				return strings.ToLower(s)
			default:
				return strings.ToLower(s[:1]) + s[1:]
			}
		},
		// camelCase converts s to camel-case
		"camelCase": func(s string) string {
			switch len(s) {
			case 0:
				return ""
			case 1:
				return strings.ToUpper(s)
			default:
				return xstrings.ToCamelCase(s)
			}
		},
		// lowerCamelCase converts s to camel-case, then converts the first character to lower-case
		"lowerCamelCase": func(s string) string {
			switch len(s) {
			case 0:
				return ""
			case 1:
				return strings.ToLower(s)
			default:
				s = xstrings.ToCamelCase(s)
				return strings.ToLower(s[:1]) + s[1:]
			}
		},
		// snakeCase converts s to snake-case
		"snakeCase": xstrings.ToSnakeCase,
		// kebabCase converts s to kebab-case
		"kebabCase": func(s string) string {
			return strings.ReplaceAll(xstrings.ToSnakeCase(s), "_", "-")
		},
		// contains returns true if sub is a substring of s and false if not
		"contains": func(sub, s string) bool {
			return strings.Contains(s, sub)
		},
		// trim removes all characters in cutset from s
		"trim": func(cutset, s string) string {
			return strings.Trim(s, cutset)
		},
		// ltrim removes all leading characters in cutset from s
		"ltrim": func(cutset, s string) string {
			return strings.TrimLeft(s, cutset)
		},
		// rtrim removes all trailing characters in cutset from s
		"rtrim": func(cutset, s string) string {
			return strings.TrimRight(s, cutset)
		},
		// trimspace removes all leading and trailing whitespace from s
		"trimspace": strings.TrimSpace,
		// pathDir returns the directory/folder portion of a file path string
		"pathDir": filepath.Dir,
		// pathBase returns the filename portion of a file path string
		"pathBase": filepath.Base,
		// pathFileName returns the file name portion of a file path string without the extension
		"pathFileName": func(s string) string {
			return strings.TrimSuffix(filepath.Base(s), filepath.Ext(s))
		},
		// pathExt returns the file extension portion of a file path string
		"pathExt": filepath.Ext,
		// pathClean "cleans" a file path string (see filepath.Clean for details)
		"pathClean": filepath.Clean,
		// absPath converts a file path string to an absolute path
		"absPath": filepath.Abs,
		// getenv returns the value of an environment variable
		"getenv": os.Getenv,
	}
)

// codeGenFunctions returns the set of custom functions available to code generation templates.
//
// This function is a shortcut for creating a template.FuncMap then calling AddStandardFunctions(),
// AddSprigFunctions(), and AddProtoFunctions() sequentially.
func codeGenFunctions(protoFile *protogen.File) template.FuncMap {
	fm := make(template.FuncMap)
	fm = addStandardFunctions(fm)
	fm = addSprigFunctions(fm)
	fm = addProtoFunctions(fm, protoFile)
	return fm
}

// addStandardFunctions constructs the basic set of template functions provided by this plug-in.
func addStandardFunctions(fm template.FuncMap) template.FuncMap {
	for k, v := range standardFuncs {
		fm[k] = v
	}
	return fm
}

// addSprigFunctions extends the passed-in set of template functions by registering all of the template
// functions provided by the Sprig (https://github.com/Masterminds/sprig) library.
func addSprigFunctions(fm template.FuncMap) template.FuncMap {
	for k, v := range sprig.TxtFuncMap() {
		fm[k] = v
	}
	return fm
}

// addProtoFunctions extends the passed-in set of template functions by registering several common
// functions for retrieving Protobuf definitions from the provided Protobuf descriptor.
func addProtoFunctions(fm template.FuncMap, protoFile *protogen.File) template.FuncMap {
	fm["protoNumberEncodeMethod"] = protoNumberEncodeMethod
	fm["getExtensions"] = getExtensions(protoFile)
	fm["allMessages"] = allMessages(protoFile)
	fm["getAdditionalImports"] = getAdditionalImports(protoFile)
	fm["getImportPrefix"] = getImportPrefix(protoFile)
	fm["mapFieldGoType"] = mapFieldGoType(protoFile)
	fm["hasRequiredFields"] = hasRequiredFields(protoFile)
	return fm
}

// map of protobuf field kind to the corresponding encoder method
var protoNumberEncodeMethodMap = map[string]string{
	"bool":    "EncodeBool",
	"uint32":  "EncodeUInt32",
	"uint64":  "EncodeUInt64",
	"int32":   "EncodeInt32",
	"int64":   "EncodeInt64",
	"sint32":  "EncodeSInt32",
	"sint64":  "EncodeSInt64",
	"fixed32": "EncodeFixed32",
	"fixed64": "EncodeFixed64",
	"float":   "EncodeFloat32",
	"double":  "EncodeFloat64",
}

// protoNumberEncodeMethod returns the name of the method on csproto.Encoder that should be called
// to write a given numeric field type using normal or packed encoding (based on the value of packed).
func protoNumberEncodeMethod(typ string, packed bool) string {
	m, exists := protoNumberEncodeMethodMap[typ]
	if !exists {
		return "XXX_UnknownType_XXX"
	}
	if packed {
		m = strings.ReplaceAll(m, "Encode", "EncodePacked")
	}
	return m
}

// getExtensions returns a list of fields that are proto2 extensions for the specified message
func getExtensions(protoFile *protogen.File) func(*protogen.Message) []*protogen.Field {
	// build a lookup of all extensions keyed by the extendee
	extensionDict := make(map[protogen.GoIdent][]*protogen.Field)
	for _, m := range protoFile.Messages {
		for _, f := range m.Extensions {
			extensionDict[f.Extendee.GoIdent] = append(extensionDict[f.Extendee.GoIdent], f)
		}
	}
	return func(msg *protogen.Message) []*protogen.Field {
		exts := extensionDict[msg.GoIdent]
		return exts
	}
}

// allMessages returns a list of all top-level and nested message definitions in protoFile
func allMessages(protoFile *protogen.File) func() []*protogen.Message {
	var queue, msgs []*protogen.Message
	queue = append(queue, protoFile.Messages...)
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		msgs = append(msgs, m)
		for _, mm := range m.Messages {
			// skip "messgaes" that represent map fields
			if mm.Desc.IsMapEntry() {
				continue
			}
			queue = append(queue, mm)
		}
	}

	return func() []*protogen.Message {
		return msgs
	}
}

// getAdditionalImports returns a list of distinct imports paths required by the fields of v, which
// must be either a single protogen.Message or a slice of messages.
func getAdditionalImports(protoFile *protogen.File) func(v interface{}) []string {
	return func(v interface{}) []string {
		paths := make(map[string]struct{})
		switch tv := v.(type) {
		case *protogen.Message:
			for _, p := range additionalImportsForType(protoFile.GoImportPath, tv) {
				paths[p] = struct{}{}
			}
		case []*protogen.Message:
			for _, m := range tv {
				for _, p := range additionalImportsForType(protoFile.GoImportPath, m) {
					paths[p] = struct{}{}
				}
			}
		default:
		}
		res := make([]string, 0, len(paths))
		for k := range paths {
			res = append(res, k)
		}
		sort.Strings(res)
		return res
	}
}

// additionalImportsForType returns a list of import paths referenced by the fields of m that are
// distinct from the package declared by p.
func additionalImportsForType(p protogen.GoImportPath, m *protogen.Message) []string {
	var res []string
	for _, fld := range m.Fields {
		switch fld.Desc.Kind() {
		case protoreflect.MessageKind:
			if ip := fld.Message.GoIdent.GoImportPath; ip != p {
				res = append(res, ip.String())
			}
		case protoreflect.EnumKind:
			if ip := fld.Enum.GoIdent.GoImportPath; ip != p {
				res = append(res, ip.String())
			}
		default:
			// nothing to do
		}
	}
	return res
}

// getImportPrefix returns the package import prefix for a given message type, or an empty string
// for messages in the same package as protoFile.
//
// Ex: For a field called Ts that is a google.protobuf.timestamp.Timestamp, the Go package is
// "google.golang.org/protobuf/types/known/timestamppb" so a local variable must be declared as timestamppb.Ts.
// This function returns "timestamppb.".
func getImportPrefix(protoFile *protogen.File) func(v interface{}) string {
	return func(v interface{}) string {
		switch tv := v.(type) {
		case *protogen.Message:
			if tv.GoIdent.GoImportPath != protoFile.GoImportPath {
				toks := strings.Split(string(tv.GoIdent.GoImportPath), "/")
				return toks[len(toks)-1] + "."
			}
		case *protogen.Enum:
			if tv.GoIdent.GoImportPath != protoFile.GoImportPath {
				toks := strings.Split(string(tv.GoIdent.GoImportPath), "/")
				return toks[len(toks)-1] + "."
			}
		default:
			return ""
		}
		return ""
	}
}

// mapFieldGoType returns the Go type definition for a given field descriptor that represents a map entry
func mapFieldGoType(protoFile *protogen.File) func(*protogen.Field) string {
	return func(field *protogen.Field) string {
		if !field.Desc.IsMap() {
			return "<<invalid>> /* field is not a map entry */"
		}
		kd, vd := field.Desc.MapKey(), field.Desc.MapValue()
		var ktype, vtype string
		switch kd.Kind() {
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
			ktype = "int32"
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			ktype = "int64"
		case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
			ktype = "uint32"
		case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			ktype = "uint64"
		case protoreflect.StringKind:
			ktype = "string"
		default:
			ktype = fmt.Sprintf("<<invalid>> /*%v*/", kd.Kind())
		}

		switch vd.Kind() {
		case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
			vtype = "int32"
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
			vtype = "int64"
		case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
			vtype = "uint32"
		case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			vtype = "uint64"
		case protoreflect.FloatKind:
			vtype = "float32"
		case protoreflect.DoubleKind:
			vtype = "float64"
		case protoreflect.StringKind:
			vtype = "string"
		case protoreflect.BytesKind:
			vtype = "[]byte"
		case protoreflect.BoolKind:
			vtype = "bool"
		case protoreflect.EnumKind:
			// TODO: dbourque - 2022-04-08
			// is the value field always the 2nd item?  or do we need to loop and check the
			// number on the descriptor?
			f := field.Message.Fields[1]
			vtype = getImportPrefix(protoFile)(f.Enum) + f.Enum.GoIdent.GoName
		case protoreflect.MessageKind:
			// TODO: dbourque - 2022-04-08
			// is the value field always the 2nd item?  or do we need to loop and check the
			// number on the descriptor?
			f := field.Message.Fields[1]
			vtype = "*" + getImportPrefix(protoFile)(f.Message) + f.Message.GoIdent.GoName
		default:
			vtype = fmt.Sprintf("<<invalid>> /*%v*/", vd.Kind())
		}
		return fmt.Sprintf("map[%s]%s", ktype, vtype)
	}
}

// msgHasRequiredField returns true if the specified message has at least 1 field marked required and
// false if not
func msgHasRequiredField(m *protogen.Message) bool {
	if m.Desc.Syntax() == protoreflect.Proto3 {
		return false
	}
	for _, f := range m.Fields {
		if f.Desc.Cardinality() == protoreflect.Required {
			return true
		}
	}
	return false
}

// hasRequiredFields returns true if at least one field in the specified message is marked required
// and false if not.
//
// If m is nil, this function returns true if *any* message in the Protobuf file has a required field
// and false if not.
func hasRequiredFields(protoFile *protogen.File) func(*protogen.Message) bool {
	anyMessageHasRequiredFields := false
	if protoFile.Desc.Syntax() == protoreflect.Proto2 {
		for _, m := range allMessages(protoFile)() {
			anyMessageHasRequiredFields = anyMessageHasRequiredFields || msgHasRequiredField(m)
		}
	}

	return func(m *protogen.Message) bool {
		if m == nil {
			return anyMessageHasRequiredFields
		}
		if m.Desc.Syntax() == protoreflect.Proto3 {
			return false
		}
		for _, f := range m.Fields {
			if f.Desc.Cardinality() == protoreflect.Required {
				return true
			}
		}
		return false
	}
}
