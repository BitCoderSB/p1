//go:build !windows

package audit

import "time"

// fileBirthTime has no portable implementation off Windows; the clone anchor
// falls back to the Git reflog and then the .git modification time.
func fileBirthTime(string) (time.Time, bool) {
	return time.Time{}, false
}
