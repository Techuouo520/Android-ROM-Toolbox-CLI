package nativebin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"artb/internal/assets"
)

var supported = map[string]struct{}{"extract.erofs": {}, "extract.ext4": {}, "extract.f2fs": {}, "mkfs.f2fs": {}, "sload.f2fs": {}, "img2simg": {}, "lpmake": {}, "lpunpack": {}, "magiskboot": {}, "mke2fs": {}, "e2fsdroid": {}, "mkfs.erofs": {}, "dtc": {}, "simg2img": {}}

type Resolver struct {
	version string
	once    sync.Once
	source  fs.FS
	store   *assets.Store
	err     error
}

func New(version string) *Resolver { return &Resolver{version: version} }

func (resolver *Resolver) Ensure(ctx context.Context, name string) (string, error) {
	if _, ok := supported[name]; !ok {
		return "", fmt.Errorf("unknown native tool %q", name)
	}
	fileName := executableName(name)
	if directory := os.Getenv("ARTB_NATIVE_DIR"); directory != "" {
		path := filepath.Join(directory, fileName)
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("locate native tool %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("locate native tool %q: not a regular file", path)
		}
		return path, nil
	}
	resolver.once.Do(resolver.initialize)
	if resolver.err != nil {
		return "", resolver.err
	}
	source := fileName
	digest, err := digestFile(resolver.source, source)
	if err != nil {
		return "", err
	}
	return resolver.store.Ensure(ctx, assets.Artifact{Name: fileName, Source: source, SHA256: digest})
}

func (resolver *Resolver) initialize() {
	resolver.source, resolver.err = embeddedFS()
	if resolver.err != nil {
		return
	}
	root, err := assets.DefaultRoot(resolver.version)
	if err != nil {
		resolver.err = err
		return
	}
	resolver.store, resolver.err = assets.New(resolver.source, root)
}

func executableName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func digestFile(source fs.FS, path string) (string, error) {
	file, err := source.Open(path)
	if err != nil {
		return "", fmt.Errorf("open embedded native tool %q: %w", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.CopyBuffer(digest, file, make([]byte, 256*1024)); err != nil {
		return "", fmt.Errorf("hash embedded native tool %q: %w", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
