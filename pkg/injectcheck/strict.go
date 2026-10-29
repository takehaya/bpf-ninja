package injectcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// strictJSON rejects ambiguous objects before encoding/json can merge them.
// Canonical field validation also removes encoding/json's case folding.
func strictJSON(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueValue(d); err != nil {
		return inputError(InputJSON, "%v", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return inputError(InputJSON, "expected one JSON value")
	}
	if err := canonicalFields(data, reflect.TypeOf(dst).Elem()); err != nil {
		return inputError(InputJSON, "%v", err)
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return inputError(InputJSON, "%v", err)
	}
	return nil
}

func uniqueValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("expected object key")
			}
			folded := strings.ToLower(key)
			if seen[folded] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[folded] = true
			if err := uniqueValue(d); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	case '[':
		for i := 0; d.More(); i++ {
			if err := uniqueValue(d); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	_, err = d.Token()
	return err
}

func canonicalFields(data []byte, typ reflect.Type) error {
	if typ == reflect.TypeFor[json.RawMessage]() || typ == reflect.TypeFor[Instructions]() {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			allowed[name] = f.Type
		}
		for key, value := range fields {
			t, ok := allowed[key]
			if !ok {
				return fmt.Errorf("unknown field %q", key)
			}
			if err := canonicalFields(value, t); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		for i, value := range values {
			if err := canonicalFields(value, typ.Elem()); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	}
	return nil
}

func requiredFields(data []byte, names ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return inputError(InputJSON, "%v", err)
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return inputError(InputMissing, "required field %q is missing or null", name)
		}
	}
	return nil
}
