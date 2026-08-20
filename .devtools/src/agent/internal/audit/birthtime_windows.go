//go:build windows

package audit

import (
	"os"
	"syscall"
	"time"
)

// fileBirthTime returns the creation time of a path on Windows, used as a proxy
// for when this working copy was cloned.
func fileBirthTime(path string) (time.Time, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(0, data.CreationTime.Nanoseconds()).UTC(), true
}
