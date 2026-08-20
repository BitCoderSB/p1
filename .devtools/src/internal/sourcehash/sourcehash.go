package sourcehash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Compute fingerprints every non-test source file and release script that can
// affect the shipped agent, plus its module dependency lockfiles. All target
// binaries embed the same digest, which lets validation detect stale artifacts.
func Compute(repositoryRoot string) (string, error) {
	paths := []string{"go.mod", "go.sum", "scripts/build-agent.ps1", "scripts/promote-agent.ps1"}
	for _, root := range []string{"agent", "internal", "scripts/sourcehash"} {
		err := filepath.WalkDir(filepath.Join(repositoryRoot, filepath.FromSlash(root)), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(repositoryRoot, path)
			if err != nil {
				return err
			}
			paths = append(paths, filepath.ToSlash(relative))
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("walk agent sources: %w", err)
		}
	}
	sort.Strings(paths)
	digest := sha256.New()
	for _, relative := range paths {
		contents, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(relative)))
		if err != nil {
			return "", fmt.Errorf("read %s: %w", relative, err)
		}
		_, _ = digest.Write([]byte(relative))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(contents)
		_, _ = digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
