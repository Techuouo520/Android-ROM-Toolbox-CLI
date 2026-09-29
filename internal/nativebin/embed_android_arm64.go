//go:build nativeembed

package nativebin

import (
	"embed"
	"io/fs"
)

// The file suffix limits this to android/arm64, whose bundle embeds only the tools CMake staged in files/android_arm64.

//go:embed files/android_arm64/*
var embedded embed.FS

func embeddedFS() (fs.FS, error) { return fs.Sub(embedded, "files/android_arm64") }
