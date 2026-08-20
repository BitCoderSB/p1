package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// validateDirectoryTree rejects links only inside a caller-owned tree. System
// ancestors are deliberately outside this boundary: on macOS, for example,
// /var is a normal platform symlink to /private/var.
func validateDirectoryTree(base, target string) error {
	baseAbsolute, err := filepath.Abs(filepath.Clean(base))
	if err != nil {
		return err
	}
	targetAbsolute, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(baseAbsolute, targetAbsolute)
	if err != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("directory is outside its trusted storage tree")
	}
	// filepath.EvalSymlinks on Windows normalizes every path prefix. Managed
	// sandboxes can deny metadata enumeration on a system ancestor while still
	// granting direct access to the repository itself. Resolve component by
	// component instead: inaccessible ancestors remain outside the trusted
	// boundary, while every accessible link is resolved and every component
	// below base is still checked explicitly by the loop below.
	canonicalBase, err := resolvePathThroughExistingAncestor(baseAbsolute)
	if err != nil {
		return fmt.Errorf("resolve trusted storage root: %w", err)
	}
	current := canonicalBase
	components := []string{}
	if relative != "." {
		components = strings.Split(relative, string(filepath.Separator))
	}
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			// A deeper component cannot exist without this parent.
			return nil
		}
		if err != nil {
			return err
		}
		linkLike, err := pathIsLinkLike(current, info)
		if err != nil {
			return err
		}
		if linkLike || !info.IsDir() {
			return fmt.Errorf("%s exists but is not a regular directory", current)
		}
	}
	return nil
}

// ensureDirectoryDurable creates a directory tree and synchronizes every new
// directory entry with its parent. File fsync alone is insufficient on POSIX
// if a power loss occurs before the first directory entry reaches disk.
func ensureDirectoryDurable(path string, mode os.FileMode) error {
	absolute, err := resolvePathThroughExistingAncestor(filepath.Clean(path))
	if err != nil {
		return err
	}
	path = absolute
	var missing []string
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			linkLike, linkErr := pathIsLinkLike(current, info)
			if linkErr != nil {
				return linkErr
			}
			if linkLike || !info.IsDir() {
				return fmt.Errorf("%s exists but is not a regular directory", current)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	for index := len(missing) - 1; index >= 0; index-- {
		parent := filepath.Dir(missing[index])
		if err := syncDirectory(parent); err != nil {
			return fmt.Errorf("sync parent directory %s: %w", parent, err)
		}
		if err := syncDirectory(missing[index]); err != nil {
			return fmt.Errorf("sync new directory %s: %w", missing[index], err)
		}
	}
	for _, created := range missing {
		info, err := os.Lstat(created)
		if err != nil {
			return err
		}
		linkLike, err := pathIsLinkLike(created, info)
		if err != nil {
			return err
		}
		if linkLike || !info.IsDir() {
			return fmt.Errorf("%s is not a regular directory after creation", created)
		}
	}
	return nil
}

func ensureDirectoryDurableUnder(base, path string, mode os.FileMode) error {
	if err := ensureDirectoryDurable(base, mode); err != nil {
		return err
	}
	if err := validateDirectoryTree(base, path); err != nil {
		return err
	}
	if err := ensureDirectoryDurable(path, mode); err != nil {
		return err
	}
	return validateDirectoryTree(base, path)
}

func regularFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	linkLike, err := pathIsLinkLike(path, info)
	if err != nil {
		return nil, err
	}
	if linkLike || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	return info, nil
}

func pathIsLinkLike(path string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}
	// Windows has reparse points that are not surfaced as ModeSymlink. Treat
	// every reparse point as a link so a lock or metadata file can never escape
	// its caller-owned storage tree.
	return pathIsReparsePoint(path)
}

// openExistingRegularFile rejects static symlinks and verifies that the object
// opened is the same regular file observed immediately before the open. The
// caller must still hold its normal per-file lock for mutation.
func openExistingRegularFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	before, err := regularFileInfo(path)
	if err != nil {
		return nil, err
	}
	// O_TRUNC acts during path resolution, before SameFile can reject a
	// regular-to-symlink swap. Open without it, verify the handle identity, and
	// only then truncate the verified handle.
	truncate := flag&os.O_TRUNC != 0
	file, err := os.OpenFile(path, flag&^os.O_TRUNC, mode)
	if err != nil {
		return nil, err
	}
	after, statErr := file.Stat()
	if statErr != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		if statErr != nil {
			return nil, statErr
		}
		return nil, fmt.Errorf("%s changed while it was being opened", filepath.Base(path))
	}
	if truncate {
		if err := file.Truncate(0); err != nil {
			_ = file.Close()
			return nil, err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	return file, nil
}
