//go:build windows

package audit

// Windows replacements use MoveFileEx with MOVEFILE_WRITE_THROUGH. There is no
// portable directory handle sync equivalent exposed by os.File.
func syncDirectory(string) error {
	return nil
}
