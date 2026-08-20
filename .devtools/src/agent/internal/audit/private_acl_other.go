//go:build !windows

package audit

import "os"

func protectPrivateFile(_, _ string) error {
	return nil
}

func protectPrivateDirectory(_, path string) error {
	return os.Chmod(path, 0o700)
}

func repairPrivateStoreACLs(_ string) error {
	return nil
}
