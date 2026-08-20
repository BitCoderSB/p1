package sourcehash

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeCoversBuildAndDigestImplementationButNotTests(t *testing.T) {
	root := t.TempDir()
	write := func(relative, contents string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.invalid/sourcehash-test\n\ngo 1.24\n")
	write("go.sum", "")
	write("scripts/build-agent.ps1", "build-v1\n")
	write("scripts/promote-agent.ps1", "promote-v1\n")
	write("scripts/sourcehash/main.go", "package main\n")
	write("agent/main.go", "package agent\n")
	write("internal/model/event.go", "package model\n")
	write("internal/sourcehash/algorithm.go", "package sourcehash\n")

	baseline, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	write("agent/main_test.go", "package agent\n")
	withTest, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if withTest != baseline {
		t.Fatal("test-only source unexpectedly changed the release digest")
	}

	write("scripts/build-agent.ps1", "build-v2\n")
	withBuildChange, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if withBuildChange == baseline {
		t.Fatal("build script change did not affect the release digest")
	}

	write("scripts/build-agent.ps1", "build-v1\n")
	write("internal/sourcehash/algorithm.go", "package sourcehash\n// digest-v2\n")
	withAlgorithmChange, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if withAlgorithmChange == baseline {
		t.Fatal("sourcehash implementation change did not affect its own release digest")
	}
}
