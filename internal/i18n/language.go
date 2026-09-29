package i18n

import (
	"os"
	"strings"
)

type Language string

const (
	English Language = "en"
	Chinese Language = "zh"
)

func FromTag(tag string) Language {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if cut := strings.IndexByte(tag, ','); cut >= 0 {
		tag = tag[:cut]
	}
	if cut := strings.IndexAny(tag, ".@"); cut >= 0 {
		tag = tag[:cut]
	}
	tag = strings.ReplaceAll(tag, "_", "-")
	if tag == "zh" || strings.HasPrefix(tag, "zh-") {
		return Chinese
	}
	return English
}

func Detect() Language {
	if tag := os.Getenv("ARTB_LANG"); tag != "" {
		return FromTag(tag)
	}
	if tag := systemTag(); tag != "" {
		return FromTag(tag)
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if tag := os.Getenv(key); tag != "" {
			return FromTag(tag)
		}
	}
	return English
}
