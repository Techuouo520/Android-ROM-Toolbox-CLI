package fsmeta

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type fsConfigEntry struct {
	uid, gid uint64
}

// readFSConfig maps absolute paths to owners; a missing file reads as empty.
func readFSConfig(path string) (map[string]fsConfigEntry, []byte, error) {
	known := map[string]fsConfigEntry{}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("read %q: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		// libcutils accepts a leading space as the root entry.
		if strings.HasPrefix(line, " ") {
			line = "/" + line
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		uid, uidErr := strconv.ParseUint(fields[1], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[2], 10, 32)
		if uidErr != nil || gidErr != nil {
			return nil, nil, fmt.Errorf("%q: invalid fs_config line %q", path, line)
		}
		known["/"+strings.TrimPrefix(fields[0], "/")] = fsConfigEntry{uid, gid}
	}
	return known, data, nil
}

// RootOwner returns the owner fs_config gives the image root, or root:root when it has no entry.
func RootOwner(path string) (uint32, uint32, error) {
	known, _, err := readFSConfig(path)
	if err != nil {
		return 0, 0, err
	}
	root := known["/"]
	return uint32(root.uid), uint32(root.gid), nil
}

// CompleteFSConfig appends default entries for tree paths the canned fs_config lacks, because the builders abort on a missing path.
func CompleteFSConfig(path string, entries []Entry) (int, error) {
	known, data, err := readFSConfig(path)
	if err != nil {
		return 0, err
	}
	var added strings.Builder
	count := 0
	for _, entry := range entries {
		if _, ok := known[entry.Path]; ok {
			continue
		}
		parent := known[parentPath(entry.Path)]
		mode := "0644"
		switch entry.Kind {
		case Dir:
			mode = "0755"
		case Symlink:
			mode = "0777"
		}
		known[entry.Path] = parent
		fmt.Fprintf(&added, "%s %d %d %s\n", entry.Path, parent.uid, parent.gid, mode)
		count++
	}
	if count == 0 {
		return 0, nil
	}
	return count, appendText(path, data, added.String())
}

func appendText(path string, existing []byte, text string) error {
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		text = "\n" + text
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	_, writeErr := file.WriteString(text)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("append %q: %w", path, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %q: %w", path, closeErr)
	}
	return nil
}

type contextSpec struct {
	exact    string
	regex    *regexp.Regexp
	fileType byte
	context  string
}

// hasMetaChars mirrors libselinux: escaped characters are literals, so extractor output stays exact.
func hasMetaChars(pattern string) bool {
	for index := 0; index < len(pattern); index++ {
		switch pattern[index] {
		case '.', '^', '$', '?', '*', '+', '|', '[', '(', '{':
			return true
		case '\\':
			index++
		}
	}
	return false
}

func unescape(pattern string) string {
	var out strings.Builder
	for index := 0; index < len(pattern); index++ {
		if pattern[index] == '\\' && index+1 < len(pattern) {
			index++
		}
		out.WriteByte(pattern[index])
	}
	return out.String()
}

// Escape quotes regular expression characters so the path matches only itself.
func Escape(path string) string {
	var out strings.Builder
	for index := 0; index < len(path); index++ {
		if strings.IndexByte(`\.^$?*+|[](){}`, path[index]) >= 0 {
			out.WriteByte('\\')
		}
		out.WriteByte(path[index])
	}
	return out.String()
}

func fileTypeMatches(want byte, kind Kind) bool {
	switch want {
	case 0:
		return true
	case 'd':
		return kind == Dir
	case '-':
		return kind == File
	case 'l':
		return kind == Symlink
	}
	return false
}

// ResolveContexts labels every entry with libselinux precedence (exact specs, then regexes from last to first), appends inherited labels for unmatched paths to the file, and returns an exact file_contexts for the builders.
func ResolveContexts(path string, entries []Entry, extra ...Entry) (string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", 0, fmt.Errorf("read %q: %w", path, err)
	}
	exact := map[string][]contextSpec{}
	var regexSpecs []contextSpec
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		spec := contextSpec{context: fields[len(fields)-1]}
		if len(fields) >= 3 && len(fields[1]) == 2 && fields[1][0] == '-' {
			spec.fileType = fields[1][1]
		}
		if !hasMetaChars(fields[0]) {
			spec.exact = unescape(fields[0])
			exact[spec.exact] = append(exact[spec.exact], spec)
			continue
		}
		spec.regex, err = regexp.Compile("^(?:" + fields[0] + ")$")
		if err != nil {
			return "", 0, fmt.Errorf("%q: file_contexts pattern %q: %w", path, fields[0], err)
		}
		regexSpecs = append(regexSpecs, spec)
	}
	if err = scanner.Err(); err != nil {
		return "", 0, fmt.Errorf("read %q: %w", path, err)
	}
	resolved := map[string]string{}
	var output, added strings.Builder
	count := 0
	lookup := func(entry Entry) string {
		// libselinux checks exact specs before regexes, each from the last line upwards.
		specs := exact[entry.Path]
		for index := len(specs) - 1; index >= 0; index-- {
			if fileTypeMatches(specs[index].fileType, entry.Kind) {
				return specs[index].context
			}
		}
		for index := len(regexSpecs) - 1; index >= 0; index-- {
			spec := regexSpecs[index]
			if fileTypeMatches(spec.fileType, entry.Kind) && spec.regex.MatchString(entry.Path) {
				return spec.context
			}
		}
		return ""
	}
	for _, entry := range append(append([]Entry{}, entries...), extra...) {
		if _, done := resolved[entry.Path]; done {
			continue
		}
		context := lookup(entry)
		if context == "" {
			context = resolved[parentPath(entry.Path)]
			if context == "" || entry.Path == "/" {
				return "", 0, fmt.Errorf("%q: no SELinux context for %s", path, entry.Path)
			}
			fmt.Fprintf(&added, "%s %s\n", Escape(entry.Path), context)
			count++
		}
		resolved[entry.Path] = context
		if context != "<<none>>" {
			fmt.Fprintf(&output, "%s %s\n", Escape(entry.Path), context)
		}
	}
	if count > 0 {
		if err = appendText(path, data, added.String()); err != nil {
			return "", 0, err
		}
	}
	return output.String(), count, nil
}
