//go:build !windows

package audit

func pathIsReparsePoint(string) (bool, error) {
	return false, nil
}
