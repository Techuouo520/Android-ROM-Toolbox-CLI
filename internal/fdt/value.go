package fdt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// isStringList repeats dtc's test for a value it prints as a string list.
func isStringList(value []byte) bool {
	if len(value) == 0 || value[len(value)-1] != 0 || value[0] == 0 {
		return false
	}
	for index, char := range value {
		if char == 0 {
			if index+1 < len(value) && value[index+1] == 0 {
				return false
			}
			continue
		}
		if (char < 0x20 || char > 0x7e) && char != '\t' && char != '\n' && char != '\r' {
			return false
		}
	}
	return true
}

// FormatValue renders a property value in dts syntax the way dtc decompiles it.
func FormatValue(value []byte) string {
	switch {
	case len(value) == 0:
		return ""
	case isStringList(value):
		parts := SplitStrings(value)
		for index, part := range parts {
			parts[index] = strconv.Quote(part)
		}
		return strings.Join(parts, ", ")
	case len(value)%4 == 0:
		cells := make([]string, len(value)/4)
		for index := range cells {
			cells[index] = fmt.Sprintf("0x%x", binary.BigEndian.Uint32(value[4*index:]))
		}
		return "<" + strings.Join(cells, " ") + ">"
	}
	parts := make([]string, len(value))
	for index, char := range value {
		parts[index] = fmt.Sprintf("%02x", char)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// FormatDecimal lists the cells of a cell-formatted value in decimal, or returns "" for strings and bytes.
func FormatDecimal(value []byte) string {
	if len(value) == 0 || len(value)%4 != 0 || isStringList(value) {
		return ""
	}
	cells := make([]string, len(value)/4)
	for index := range cells {
		cells[index] = strconv.FormatUint(uint64(binary.BigEndian.Uint32(value[4*index:])), 10)
	}
	return strings.Join(cells, " ")
}

// ParseValue encodes dts syntax ("strings", <cells>, /bits/ N <cells>, [bytes]); bare numbers are cells so shells need no quoting of < and >.
func ParseValue(text string) ([]byte, error) {
	var out []byte
	rest := strings.TrimSpace(text)
	if rest != "" && !strings.ContainsAny(rest[:1], "\"<[/") {
		return ParseValue("<" + rest + ">")
	}
	for rest != "" {
		var err error
		switch {
		case rest[0] == '"':
			var quoted string
			if quoted, err = strconv.QuotedPrefix(rest); err != nil {
				return nil, fmt.Errorf("bad string in %q: %w", text, err)
			}
			value, _ := strconv.Unquote(quoted)
			out, rest = append(append(out, value...), 0), rest[len(quoted):]
		case rest[0] == '<' || strings.HasPrefix(rest, "/bits/"):
			bits := 32
			if strings.HasPrefix(rest, "/bits/") {
				fields := strings.Fields(rest[len("/bits/"):])
				if len(fields) == 0 {
					return nil, fmt.Errorf("missing width after /bits/ in %q", text)
				}
				width := strings.SplitN(fields[0], "<", 2)[0]
				if bits, err = strconv.Atoi(width); err != nil || (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
					return nil, fmt.Errorf("unsupported /bits/ width %q", width)
				}
				rest = strings.TrimSpace(strings.TrimSpace(rest[len("/bits/"):])[len(width):])
			}
			end := strings.IndexByte(rest, '>')
			if !strings.HasPrefix(rest, "<") || end < 0 {
				return nil, fmt.Errorf("unterminated <cells> in %q", text)
			}
			for _, field := range strings.Fields(rest[1:end]) {
				number, err := strconv.ParseUint(field, 0, bits)
				if err != nil {
					return nil, fmt.Errorf("bad %d-bit cell %q: %w", bits, field, err)
				}
				switch bits {
				case 8:
					out = append(out, byte(number))
				case 16:
					out = binary.BigEndian.AppendUint16(out, uint16(number))
				case 32:
					out = binary.BigEndian.AppendUint32(out, uint32(number))
				default:
					out = binary.BigEndian.AppendUint64(out, number)
				}
			}
			rest = rest[end+1:]
		case rest[0] == '[':
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return nil, fmt.Errorf("unterminated [bytes] in %q", text)
			}
			digits := strings.Join(strings.Fields(rest[1:end]), "")
			if len(digits)%2 != 0 {
				return nil, fmt.Errorf("odd number of hex digits in %q", rest[:end+1])
			}
			for index := 0; index < len(digits); index += 2 {
				number, err := strconv.ParseUint(digits[index:index+2], 16, 8)
				if err != nil {
					return nil, fmt.Errorf("bad byte %q: %w", digits[index:index+2], err)
				}
				out = append(out, byte(number))
			}
			rest = rest[end+1:]
		default:
			return nil, fmt.Errorf("value %q must use \"string\", <cells>, /bits/ N <cells> or [bytes]", text)
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return nil, errors.New("value components must be separated by commas")
		}
		rest = strings.TrimSpace(rest[1:])
		if rest == "" {
			return nil, errors.New("trailing comma in value")
		}
	}
	return out, nil
}
