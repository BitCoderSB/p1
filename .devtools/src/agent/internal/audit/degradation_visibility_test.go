package audit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

// A project.json naming an adapter this build does not know must never take the
// whole file down with it. That file is tracked, so a newer one arrives with an
// ordinary git pull while the binary may still be the previous release. When the
// unknown name invalidated the config, loadProjectConfig failed, which failed
// DiscoverRepository, which made capture exit 2 — and the provider then REFUSED
// the prompt, for all three existing adapters, until somebody intervened.
func TestUnknownAdapterDoesNotInvalidateTheProjectConfig(t *testing.T) {
	base := ProjectConfig{
		ServerURL:      "http://localhost:8080",
		OrganizationID: compiledOrganizationID,
		ProjectName:    compiledProjectName,
		RetentionDays:  365,
		RedactSecrets:  true,
		EnabledTools: []string{
			model.ToolClaudeCode, model.ToolCodex, model.ToolCopilotCLI,
		},
	}

	future := base
	future.EnabledTools = append(append([]string{}, base.EnabledTools...), "antigravity")
	if err := validateProjectConfig(future); err != nil {
		t.Fatalf("an unknown adapter must be ignored, not rejected: %v", err)
	}

	// Removing one of the three is still how capture would be silenced, so it
	// must stay refused even when an unknown adapter is present.
	for _, missing := range []string{
		model.ToolClaudeCode, model.ToolCodex, model.ToolCopilotCLI,
	} {
		reduced := base
		reduced.EnabledTools = nil
		for _, tool := range base.EnabledTools {
			if tool != missing {
				reduced.EnabledTools = append(reduced.EnabledTools, tool)
			}
		}
		reduced.EnabledTools = append(reduced.EnabledTools, "antigravity")
		if err := validateProjectConfig(reduced); err == nil {
			t.Fatalf("dropping %s must still be refused", missing)
		}
	}

	duplicated := base
	duplicated.EnabledTools = append(append([]string{}, base.EnabledTools...), model.ToolCodex)
	if err := validateProjectConfig(duplicated); err == nil {
		t.Fatal("a duplicate adapter must still be refused")
	}
}

// The agent routes most degradations to the health log instead of failing, so a
// session never ends and a commit never breaks over a bad pass. That trade-off
// only holds if something reads the log back: until now nothing did, and every
// one of those warnings was filed where nobody would ever look.
func TestStatusSurfacesRecordedHealthIncidents(t *testing.T) {
	useTestConfigDirectory(t)
	repository := newTestRepository(t, "http://localhost:8080", nil)
	enableTestLocalStore(t, repository)
	t.Chdir(repository.Root)

	if err := preparePrivateLocalStore(repository.Root); err != nil {
		t.Fatalf("prepare local store: %v", err)
	}
	if summary := summarizeLocalHealth(repository.Root); summary.Total != 0 {
		t.Fatalf("an absent health log must summarise as empty, got %d", summary.Total)
	}

	const incident = "synthetic degradation for the status view"
	recordLocalHealth(repository.Root, incident)

	summary := summarizeLocalHealth(repository.Root)
	if summary.Total != 1 || len(summary.Recent) != 1 {
		t.Fatalf("health summary = %#v, want exactly one entry", summary)
	}

	var output bytes.Buffer
	if err := Status(&output); err != nil {
		t.Fatalf("Status() = %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "Incidencias registradas") {
		t.Fatalf("Status() must surface recorded incidents:\n%s", text)
	}
	if !strings.Contains(text, incident) {
		t.Fatalf("Status() must show the recorded entry:\n%s", text)
	}
}
