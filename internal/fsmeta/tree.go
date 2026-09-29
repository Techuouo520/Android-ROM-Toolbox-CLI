// Package fsmeta scans extracted partition trees and prepares fs_config and file_contexts for the image builders.
package fsmeta

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"artb/internal/cpu"
)

type Kind byte

const (
	File Kind = iota
	Dir
	Symlink
)

// Entry is one tree member keyed by its absolute in-image path such as /etc/build.prop.
type Entry struct {
	Path    string
	Kind    Kind
	Size    int64
	ModTime int64
	Target  string
}

// Scan walks root and reports every entry with authoritative metadata from Lstat, reading directories on all logical cores.
func Scan(root string) ([]Entry, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("scan %q: %w", root, err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("scan %q: not a directory", root)
	}
	var (
		mutex    sync.Mutex
		entries  = []Entry{{Path: "/", Kind: Dir, ModTime: rootInfo.ModTime().UnixNano()}}
		firstErr error
		group    sync.WaitGroup
		slots    = make(chan struct{}, cpu.Logical())
	)
	var visit func(dir, name string)
	visit = func(dir, name string) {
		defer group.Done()
		slots <- struct{}{}
		children, err := os.ReadDir(dir)
		var local []Entry
		var subdirs [][2]string
		for _, child := range children {
			if err != nil {
				break
			}
			path := filepath.Join(dir, child.Name())
			childName := strings.TrimSuffix(name, "/") + "/" + child.Name()
			// Directory listings can carry stale sizes on Windows, so read each entry itself.
			var info fs.FileInfo
			info, err = os.Lstat(path)
			if err != nil {
				break
			}
			item := Entry{Path: childName, Size: info.Size(), ModTime: info.ModTime().UnixNano()}
			if info.IsDir() {
				item.Kind, item.Size = Dir, 0
				subdirs = append(subdirs, [2]string{path, childName})
			} else {
				var target string
				var link bool
				if target, link, err = symlinkTarget(path, info); err != nil {
					break
				}
				if link {
					item.Kind, item.Target = Symlink, target
				}
			}
			local = append(local, item)
		}
		<-slots
		mutex.Lock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
		entries = append(entries, local...)
		failed := firstErr != nil
		mutex.Unlock()
		if failed {
			return
		}
		for _, subdir := range subdirs {
			group.Add(1)
			go visit(subdir[0], subdir[1])
		}
	}
	group.Add(1)
	visit(root, "/")
	group.Wait()
	if firstErr != nil {
		return nil, fmt.Errorf("scan %q: %w", root, firstErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// Fingerprint identifies the tree state plus the config files, so pack can skip unchanged partitions.
func Fingerprint(entries []Entry, configs ...string) (string, error) {
	digest := sha256.New()
	for _, entry := range entries {
		if _, err := fmt.Fprintf(digest, "%s\x00%d\x00%d\x00%d\x00%s\n", entry.Path, entry.Kind, entry.Size, entry.ModTime, entry.Target); err != nil {
			return "", err
		}
	}
	for _, config := range configs {
		file, err := os.Open(config)
		if err != nil {
			return "", fmt.Errorf("open %q: %w", config, err)
		}
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", fmt.Errorf("read %q: %w", config, copyErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close %q: %w", config, closeErr)
		}
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func parentPath(path string) string {
	if path == "/" {
		return "/"
	}
	index := strings.LastIndexByte(path, '/')
	if index <= 0 {
		return "/"
	}
	return path[:index]
}
