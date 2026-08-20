package audit

import (
	"strconv"
	"strings"
)

// codexVersionAtLeast is the stable-release floor helper used by the provider
// runtime verifiers. Prereleases are intentionally rejected: hook semantics
// are accepted only once they are part of a stable provider release.
func codexVersionAtLeast(value string, wantMajor, wantMinor, wantPatch int) bool {
	normalized := strings.TrimPrefix(strings.TrimSpace(value), "v")
	if strings.Contains(normalized, "-") {
		return false
	}
	if suffix := strings.Index(normalized, "+"); suffix >= 0 {
		normalized = normalized[:suffix]
	}
	parts := strings.Split(normalized, ".")
	if len(parts) != 3 {
		return false
	}
	got := [3]int{}
	for index, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 {
			return false
		}
		got[index] = parsed
	}
	want := [3]int{wantMajor, wantMinor, wantPatch}
	for index := range got {
		if got[index] != want[index] {
			return got[index] > want[index]
		}
	}
	return true
}

// codexRecoveryVersionAtLeast applies the more conservative compatibility
// policy used for transcript recovery. Stable releases are accepted at the
// requested floor. A well-formed prerelease is accepted only when its core
// version is strictly newer than that floor: for example, 0.145.0-alpha is
// safely beyond a 0.134.0 format floor, while 0.134.0-rc remains below the
// corresponding stable release.
//
// Runtime hook verification intentionally continues to use
// codexVersionAtLeast, which rejects every prerelease.
func codexRecoveryVersionAtLeast(value string, wantMajor, wantMinor, wantPatch int) bool {
	got, prerelease, ok := parseCodexRecoveryVersion(value)
	if !ok {
		return false
	}
	want := [3]int{wantMajor, wantMinor, wantPatch}
	comparison := compareCodexVersionCore(got, want)
	if prerelease {
		return comparison > 0
	}
	return comparison >= 0
}

func parseCodexRecoveryVersion(value string) ([3]int, bool, bool) {
	var core [3]int
	normalized := strings.TrimPrefix(strings.TrimSpace(value), "v")
	if normalized == "" {
		return core, false, false
	}

	versionPart := normalized
	if plus := strings.Index(versionPart, "+"); plus >= 0 {
		if strings.Contains(versionPart[plus+1:], "+") ||
			!validSemverIdentifiers(versionPart[plus+1:], false) {
			return core, false, false
		}
		versionPart = versionPart[:plus]
	}

	prerelease := false
	if dash := strings.Index(versionPart, "-"); dash >= 0 {
		if !validSemverIdentifiers(versionPart[dash+1:], true) {
			return core, false, false
		}
		prerelease = true
		versionPart = versionPart[:dash]
	}

	parts := strings.Split(versionPart, ".")
	if len(parts) != len(core) {
		return core, false, false
	}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return core, false, false
		}
		parsed, err := strconv.Atoi(part)
		if err != nil || parsed < 0 {
			return core, false, false
		}
		core[index] = parsed
	}
	return core, prerelease, true
}

func validSemverIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, character := range identifier {
			switch {
			case character >= '0' && character <= '9':
			case character >= 'A' && character <= 'Z':
				numeric = false
			case character >= 'a' && character <= 'z':
				numeric = false
			case character == '-':
				numeric = false
			default:
				return false
			}
		}
		if rejectNumericLeadingZero &&
			numeric &&
			len(identifier) > 1 &&
			identifier[0] == '0' {
			return false
		}
	}
	return true
}

func compareCodexVersionCore(left, right [3]int) int {
	for index := range left {
		switch {
		case left[index] < right[index]:
			return -1
		case left[index] > right[index]:
			return 1
		}
	}
	return 0
}
