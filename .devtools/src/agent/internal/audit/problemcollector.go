package audit

import (
	"errors"
	"fmt"
)

// Keep diagnostics useful without letting adversarial provider history grow an
// unbounded []error in memory. The first problems retain errors.Is/errors.As
// behavior; the final summary records how many additional problems were
// suppressed.
const maxCollectedProblems = 32

type problemCollector struct {
	items      []error
	suppressed uint64
}

func (collector *problemCollector) Add(problem error) {
	if problem == nil {
		return
	}
	if len(collector.items) < maxCollectedProblems {
		collector.items = append(collector.items, problem)
		return
	}
	if collector.suppressed != ^uint64(0) {
		collector.suppressed++
	}
}

func (collector *problemCollector) Err(scope string) error {
	if len(collector.items) == 0 && collector.suppressed == 0 {
		return nil
	}
	problems := make([]error, 0, len(collector.items)+1)
	problems = append(problems, collector.items...)
	if collector.suppressed != 0 {
		problems = append(
			problems,
			fmt.Errorf("%s: %d additional problems suppressed", scope, collector.suppressed),
		)
	}
	return errors.Join(problems...)
}
