package audit

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProblemCollectorBoundsDiagnosticsAndPreservesWrappedErrors(t *testing.T) {
	sentinel := errors.New("sentinel")
	var collector problemCollector
	collector.Add(fmt.Errorf("first: %w", sentinel))
	for i := 1; i < maxCollectedProblems+5; i++ {
		collector.Add(fmt.Errorf("problem %d", i))
	}

	err := collector.Err("test scope")
	if !errors.Is(err, sentinel) {
		t.Fatal("problemCollector lost errors.Is behavior for retained diagnostics")
	}
	if !strings.Contains(err.Error(), "5 additional problems suppressed") {
		t.Fatalf("problemCollector summary = %q; want suppressed count", err)
	}
}

func TestProblemCollectorIgnoresNilAndReturnsNilWhenEmpty(t *testing.T) {
	var collector problemCollector
	collector.Add(nil)
	if err := collector.Err("test scope"); err != nil {
		t.Fatalf("empty problemCollector = %v; want nil", err)
	}
}
