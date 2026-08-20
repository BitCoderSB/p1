package repositoryidentity

import "testing"

func TestNormalizeIsIdempotentAcrossCloneTransports(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "https://git.example/acme/repo.git", want: "git.example/acme/repo"},
		{input: "ssh://git@git.example/acme/repo.git", want: "git.example/acme/repo"},
		{input: "git@git.example:acme/repo.git", want: "git.example/acme/repo"},
		{input: "git@git.example:8443/repo.git", want: "git.example/8443/repo"},
		{input: "https://git.example/8443/repo.git", want: "git.example/8443/repo"},
		{input: "https://git.example:8443/acme/repo.git", want: "git.example:8443/acme/repo"},
		{input: "https://[2001:db8::1]:8443/acme/repo.git", want: "[2001:db8::1]:8443/acme/repo"},
		{input: "ssh://git@[2001:db8::1]/acme/repo.git", want: "[2001:db8::1]/acme/repo"},
		{input: "git@[2001:db8::1]:acme/repo.git", want: "[2001:db8::1]/acme/repo"},
	}
	for _, tt := range tests {
		first, err := Normalize(tt.input)
		if err != nil || first != tt.want {
			t.Fatalf("Normalize(%q) = %q, %v; want %q", tt.input, first, err, tt.want)
		}
		second, err := Normalize(first)
		if err != nil || second != first {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q (%v)", tt.input, first, second, err)
		}
	}
}
