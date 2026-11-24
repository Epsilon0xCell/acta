// Package canon provides a strict JSON value model and a canonical
// JSON encoder. The canonical form follows the prototype corpus
// convention stated in the specification (Section 16.10 decision
// 16): object keys sorted, no insignificant whitespace, UTF-8 with
// non-ASCII characters escaped. The parser rejects duplicate object
// keys and trailing data, and preserves the exact lexical kind of
// every scalar so the strictness table of Section 16.10 decision 24
// can distinguish integers from floats, strings, booleans and nulls.
//
// Author: Gavin Blacklock
package canon

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Kind enumerates the JSON value kinds.
type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindFloat
	KindString
	KindArray
	KindObject
)

// Value is a parsed JSON value. Object members keep source order;
// canonical encoding sorts them.
type Value struct {
	Kind  Kind
	Bool  bool
	Int   int64
	Float float64
	Raw   string // raw number literal for floats
	Str   string
	Arr   []*Value
	Keys  []string
	Obj   map[string]*Value
}

// Null is the shared null value.
var Null = &Value{Kind: KindNull}

// Parse parses exactly one JSON document strictly.
func Parse(data []byte) (*Value, error) {
	p := &parser{s: string(data)}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("trailing data at offset %d", p.i)
	}
	return v, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) ws() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r') {
		p.i++
	}
}

func (p *parser) value() (*Value, error) {
	p.ws()
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, Str: s}, nil
	case c == 't':
		if strings.HasPrefix(p.s[p.i:], "true") {
			p.i += 4
			return &Value{Kind: KindBool, Bool: true}, nil
		}
	case c == 'f':
		if strings.HasPrefix(p.s[p.i:], "false") {
			p.i += 5
			return &Value{Kind: KindBool}, nil
		}
	case c == 'n':
		if strings.HasPrefix(p.s[p.i:], "null") {
			p.i += 4
			return Null, nil
		}
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, fmt.Errorf("unexpected character %q at offset %d", p.s[p.i], p.i)
}

func (p *parser) number() (*Value, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	isFloat := false
	if p.i < len(p.s) && p.s[p.i] == '.' {
		isFloat = true
		p.i++
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		isFloat = true
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	}
	raw := p.s[start:p.i]
	if raw == "" || raw == "-" {
		return nil, fmt.Errorf("bad number at offset %d", start)
	}
	if isFloat {
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("bad number %q", raw)
		}
		return &Value{Kind: KindFloat, Float: f, Raw: raw}, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("integer %q out of range", raw)
	}
	return &Value{Kind: KindInt, Int: n, Raw: raw}, nil
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", fmt.Errorf("bad escape at end of input")
			}
			switch e := p.s[p.i]; e {
			case '"', '\\', '/':
				b.WriteByte(e)
				p.i++
			case 'b':
				b.WriteByte('\b')
				p.i++
			case 'f':
				b.WriteByte('\f')
				p.i++
			case 'n':
				b.WriteByte('\n')
				p.i++
			case 'r':
				b.WriteByte('\r')
				p.i++
			case 't':
				b.WriteByte('\t')
				p.i++
			case 'u':
				if p.i+4 >= len(p.s) {
					return "", fmt.Errorf("bad unicode escape")
				}
				hex := p.s[p.i+1 : p.i+5]
				n, err := strconv.ParseUint(hex, 16, 32)
				if err != nil {
					return "", fmt.Errorf("bad unicode escape %q", hex)
				}
				p.i += 5
				r := rune(n)
				if utf16.IsSurrogate(r) && p.i+5 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
					hex2 := p.s[p.i+2 : p.i+6]
					n2, err2 := strconv.ParseUint(hex2, 16, 32)
					if err2 == nil {
						if dec := utf16.DecodeRune(r, rune(n2)); dec != unicodeReplacement {
							b.WriteRune(dec)
							p.i += 6
							continue
						}
					}
				}
				b.WriteRune(r)
			default:
				return "", fmt.Errorf("bad escape %q", e)
			}
		case c < 0x20:
			return "", fmt.Errorf("control character in string at offset %d", p.i)
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", fmt.Errorf("unterminated string")
}

const unicodeReplacement = '\uFFFD'

func (p *parser) object() (*Value, error) {
	p.i++
	v := &Value{Kind: KindObject, Obj: map[string]*Value{}}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, fmt.Errorf("expected object key at offset %d", p.i)
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := v.Obj[k]; dup {
			return nil, fmt.Errorf("duplicate object key %q", k)
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("expected ':' at offset %d", p.i)
		}
		p.i++
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		v.Keys = append(v.Keys, k)
		v.Obj[k] = val
		p.ws()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("unterminated object")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			return v, nil
		}
		return nil, fmt.Errorf("expected ',' or '}' at offset %d", p.i)
	}
}

func (p *parser) array() (*Value, error) {
	p.i++
	v := &Value{Kind: KindArray}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return v, nil
	}
	for {
		val, err := p.value()
		if err != nil {
			return nil, err
		}
		v.Arr = append(v.Arr, val)
		p.ws()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("unterminated array")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			return v, nil
		}
		return nil, fmt.Errorf("expected ',' or ']' at offset %d", p.i)
	}
}

// Get returns the named object member, or nil when absent.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	return v.Obj[key]
}

// Has reports whether the named member is present (even as null).
func (v *Value) Has(key string) bool {
	if v == nil || v.Kind != KindObject {
		return false
	}
	_, ok := v.Obj[key]
	return ok
}

// SortedKeys returns the object keys in canonical (bytewise) order.
func (v *Value) SortedKeys() []string {
	ks := make([]string, len(v.Keys))
	copy(ks, v.Keys)
	sort.Strings(ks)
	return ks
}

// Encode returns the canonical encoding of the value.
func Encode(v *Value) []byte {
	var b strings.Builder
	encode(&b, v)
	return []byte(b.String())
}

func encode(b *strings.Builder, v *Value) {
	switch v.Kind {
	case KindNull:
		b.WriteString("null")
	case KindBool:
		if v.Bool {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case KindInt:
		b.WriteString(strconv.FormatInt(v.Int, 10))
	case KindFloat:
		b.WriteString(formatFloat(v.Float))
	case KindString:
		encodeString(b, v.Str)
	case KindArray:
		b.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				b.WriteByte(',')
			}
			encode(b, e)
		}
		b.WriteByte(']')
	case KindObject:
		b.WriteByte('{')
		for i, k := range v.SortedKeys() {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, k)
			b.WriteByte(':')
			encode(b, v.Obj[k])
		}
		b.WriteByte('}')
	}
}

// formatFloat renders a float the way the reference canonical
// encoder does for the values that can appear in a payload: the
// shortest round-trip decimal form.
func formatFloat(f float64) string {
	if f == float64(int64(f)) && f < 1e15 && f > -1e15 {
		return strconv.FormatInt(int64(f), 10) + ".0"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// encodeString writes a string with non-ASCII characters escaped,
// matching the reference canonical encoder.
func encodeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 || r > 0x7E {
				if r > 0xFFFF {
					r1, r2 := utf16.EncodeRune(r)
					fmt.Fprintf(b, "\\u%04x\\u%04x", r1, r2)
				} else {
					fmt.Fprintf(b, "\\u%04x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// Equal reports deep structural equality of two values. Numbers
// compare by kind and value: an integer never equals a float.
func Equal(a, b *Value) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindNull:
		return true
	case KindBool:
		return a.Bool == b.Bool
	case KindInt:
		return a.Int == b.Int
	case KindFloat:
		return a.Float == b.Float
	case KindString:
		return a.Str == b.Str
	case KindArray:
		if len(a.Arr) != len(b.Arr) {
			return false
		}
		for i := range a.Arr {
			if !Equal(a.Arr[i], b.Arr[i]) {
				return false
			}
		}
		return true
	case KindObject:
		if len(a.Obj) != len(b.Obj) {
			return false
		}
		for k, av := range a.Obj {
			bv, ok := b.Obj[k]
			if !ok || !Equal(av, bv) {
				return false
			}
		}
		return true
	}
	return false
}

// Clone returns a deep copy.
func Clone(v *Value) *Value {
	if v == nil {
		return nil
	}
	c := *v
	if v.Kind == KindArray {
		c.Arr = make([]*Value, len(v.Arr))
		for i, e := range v.Arr {
			c.Arr[i] = Clone(e)
		}
	}
	if v.Kind == KindObject {
		c.Keys = append([]string(nil), v.Keys...)
		c.Obj = make(map[string]*Value, len(v.Obj))
		for k, e := range v.Obj {
			c.Obj[k] = Clone(e)
		}
	}
	return &c
}

// Without returns a copy of an object value with the named keys
// removed.
func (v *Value) Without(keys ...string) *Value {
	c := Clone(v)
	if c.Kind != KindObject {
		return c
	}
	drop := map[string]bool{}
	for _, k := range keys {
		drop[k] = true
	}
	kept := c.Keys[:0]
	for _, k := range c.Keys {
		if drop[k] {
			delete(c.Obj, k)
		} else {
			kept = append(kept, k)
		}
	}
	c.Keys = kept
	return c
}

// Constructors used by builders and tests.

func Str(s string) *Value { return &Value{Kind: KindString, Str: s} }
func Int(n int64) *Value  { return &Value{Kind: KindInt, Int: n, Raw: strconv.FormatInt(n, 10)} }
func Bool(x bool) *Value  { return &Value{Kind: KindBool, Bool: x} }
func Arr(items ...*Value) *Value {
	return &Value{Kind: KindArray, Arr: items}
}

// Obj builds an object from alternating keys and values, in the
// order given.
func Obj(pairs ...interface{}) *Value {
	v := &Value{Kind: KindObject, Obj: map[string]*Value{}}
	for i := 0; i+1 < len(pairs); i += 2 {
		k := pairs[i].(string)
		v.Keys = append(v.Keys, k)
		v.Obj[k] = pairs[i+1].(*Value)
	}
	return v
}

// Set assigns a member on an object value.
func (v *Value) Set(key string, val *Value) {
	if _, ok := v.Obj[key]; !ok {
		v.Keys = append(v.Keys, key)
	}
	v.Obj[key] = val
}

// StrOr returns the string value, or "" when absent or not a string.
func (v *Value) StrOr(def string) string {
	if v != nil && v.Kind == KindString {
		return v.Str
	}
	return def
}

// IsInt reports whether the value is a JSON integer.
func (v *Value) IsInt() bool { return v != nil && v.Kind == KindInt }

var _ = utf8.RuneLen
