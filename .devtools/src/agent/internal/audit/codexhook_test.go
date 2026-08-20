package audit

import "testing"

func TestCodexRecoveryVersionPolicy(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		version string
		want    bool
	}{
		{name: "minimum stable", version: "0.134.0", want: true},
		{name: "later stable", version: "0.145.0", want: true},
		{name: "floor prerelease", version: "0.134.0-rc.1", want: false},
		{name: "later patch prerelease", version: "0.134.1-alpha.1", want: true},
		{name: "real alpha 145", version: "0.145.0-alpha.18", want: true},
		{name: "real alpha 146", version: "0.146.0-alpha.3", want: true},
		{name: "older prerelease", version: "0.133.99-alpha.1", want: false},
		{name: "empty prerelease", version: "0.145.0-", want: false},
		{name: "empty prerelease identifier", version: "0.145.0-alpha..1", want: false},
		{name: "invalid prerelease character", version: "0.145.0-alpha_1", want: false},
		{name: "numeric prerelease leading zero", version: "0.145.0-alpha.018", want: false},
		{name: "empty build metadata", version: "0.145.0-alpha.18+", want: false},
		{name: "multiple build separators", version: "0.145.0-alpha.18+one+two", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := codexRecoveryVersionAtLeast(testCase.version, 0, 134, 0); got != testCase.want {
				t.Fatalf(
					"codexRecoveryVersionAtLeast(%q, 0, 134, 0) = %t; want %t",
					testCase.version,
					got,
					testCase.want,
				)
			}
		})
	}
}
