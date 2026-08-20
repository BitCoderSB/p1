package audit

import "errors"

// scanAndStoreAllPrompts imports not-yet-recorded prompts for every supported
// AI tool — Codex, Claude Code and supported GitHub Copilot VS Code sessions —
// from their local transcript logs into this repository's registry. This is an
// explicit contingency path only: normal bootstrap, viewing, reporting and
// commits rely on direct durable hooks and never traverse global histories.
//
// Each scanner is independent and best-effort: a tool that is not installed, or
// whose logs are unreadable, simply contributes zero and never blocks the
// others. Returns the total number of prompts newly added.
func scanAndStoreAllPrompts(repo RepositoryInfo) (int, error) {
	total := 0
	var problems []error
	for _, scan := range []func(RepositoryInfo) (int, error){
		scanAndStoreCodexPrompts,
		scanAndStoreClaudePrompts,
		scanAndStoreCopilotPrompts,
		scanAndStoreAntigravityPrompts,
	} {
		added, err := scan(repo)
		total += added
		if err != nil {
			problems = append(problems, err)
		}
	}
	if len(problems) > 0 {
		recordLocalHealth(repo.Root, "one or more prompt-history scanners reported an error")
	}
	return total, errors.Join(problems...)
}
