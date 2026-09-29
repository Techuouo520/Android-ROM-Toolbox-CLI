package assets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const copyBufferSize = 256 * 1024

type Artifact struct {
	Name   string
	Source string
	SHA256 string
}

type Store struct {
	source fs.FS
	root   string
	mu     sync.Mutex
}

func New(source fs.FS, root string) (*Store, error) {
	if source == nil {
		return nil, errors.New("create asset store: nil source filesystem")
	}
	if root == "" {
		return nil, errors.New("create asset store: empty cache root")
	}
	return &Store{source: source, root: root}, nil
}

func DefaultRoot(version string) (string, error) {
	if !validSegment(version) {
		return "", fmt.Errorf("resolve asset cache: invalid version %q", version)
	}
	cache, err := os.UserCacheDir()
	// adb shell runs with HOME=/ which is read-only; Android's TempDir ($TMPDIR, else /data/local/tmp) is writable and executable.
	if runtime.GOOS == "android" && (err != nil || os.MkdirAll(cache, 0o755) != nil) {
		cache, err = os.TempDir(), nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve user cache: %w", err)
	}
	return filepath.Join(cache, "artb", "bin", version, runtime.GOOS+"-"+runtime.GOARCH), nil
}

func (store *Store) Ensure(ctx context.Context, artifact Artifact) (string, error) {
	expected, err := validateArtifact(artifact)
	if err != nil {
		return "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(store.root, 0o755); err != nil {
		return "", fmt.Errorf("create asset cache %q: %w", store.root, err)
	}
	target := filepath.Join(store.root, artifact.Name)
	valid, err := validCachedFile(ctx, target, expected)
	if err != nil {
		return "", err
	}
	if valid {
		return target, nil
	}
	source, err := store.source.Open(artifact.Source)
	if err != nil {
		return "", fmt.Errorf("open embedded asset %q: %w", artifact.Source, err)
	}
	defer source.Close()
	temporary, err := os.CreateTemp(store.root, "."+artifact.Name+"-*")
	if err != nil {
		return "", fmt.Errorf("create temporary asset: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	digest := sha256.New()
	if err := copyWithContext(ctx, io.MultiWriter(temporary, digest), source); err != nil {
		return "", fmt.Errorf("extract asset %q: %w", artifact.Name, err)
	}
	if !equalDigest(digest, expected) {
		return "", fmt.Errorf("extract asset %q: sha256 mismatch", artifact.Name)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync asset %q: %w", artifact.Name, err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close asset %q: %w", artifact.Name, err)
	}
	closed = true
	if err := os.Chmod(temporaryPath, 0o755); err != nil {
		return "", fmt.Errorf("set asset mode %q: %w", artifact.Name, err)
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("replace asset %q: %w", artifact.Name, err)
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return "", fmt.Errorf("install asset %q: %w", artifact.Name, err)
	}
	return target, nil
}

func validateArtifact(artifact Artifact) ([]byte, error) {
	if !validSegment(artifact.Name) {
		return nil, fmt.Errorf("invalid asset name %q", artifact.Name)
	}
	if !fs.ValidPath(artifact.Source) || artifact.Source == "." {
		return nil, fmt.Errorf("invalid asset source %q", artifact.Source)
	}
	expected, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, fmt.Errorf("invalid sha256 for asset %q", artifact.Name)
	}
	return expected, nil
}

func validCachedFile(ctx context.Context, path string, expected []byte) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat cached asset %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("cached asset %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open cached asset %q: %w", path, err)
	}
	defer file.Close()
	digest := sha256.New()
	if err := copyWithContext(ctx, digest, file); err != nil {
		return false, fmt.Errorf("verify cached asset %q: %w", path, err)
	}
	return equalDigest(digest, expected), nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) error {
	buffer := make([]byte, copyBufferSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			written, writeErr := destination.Write(buffer[:count])
			if writeErr != nil {
				return writeErr
			}
			if written != count {
				return io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func equalDigest(digest hash.Hash, expected []byte) bool {
	return bytes.Equal(digest.Sum(nil), expected)
}
func validSegment(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, `/\\<>:"|?*`)
}
