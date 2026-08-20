package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestProjectIdentityAndAllAdaptersAreCompiledIntoAgent(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ProjectConfig)
	}{
		{
			name: "organization",
			mutate: func(config *ProjectConfig) {
				config.OrganizationID = "other-organization"
			},
		},
		{
			name: "project",
			mutate: func(config *ProjectConfig) {
				config.ProjectName = "other-project"
			},
		},
		{
			name: "missing-adapter",
			mutate: func(config *ProjectConfig) {
				config.EnabledTools = []string{model.ToolClaudeCode, model.ToolCodex}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newTestRepository(t, "http://localhost:8080", nil)
			config, err := loadProjectConfig(repository.Root)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&config)
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(repository.Root, filepath.FromSlash(projectConfigPath))
			if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := DiscoverRepository(repository.Root); err == nil {
				t.Fatal("modified project identity/adapters were accepted")
			}
		})
	}
}

func TestInvalidProjectMutationCannotRemoveAuthoritativeBackup(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", nil)
	enableTestLocalStore(t, repository)
	event := sampleEvent("project-mutation-preserved", "synthetic prompt")
	if err := writeLocalEvent(repository.Root, event); err != nil {
		t.Fatal(err)
	}
	path := authoritativePath(repository.Root, event.UserID)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	config, err := loadProjectConfig(repository.Root)
	if err != nil {
		t.Fatal(err)
	}
	config.ProjectName = "mutated-project"
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(repository.Root, filepath.FromSlash(projectConfigPath))
	if err := os.WriteFile(configPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileRegistry(repository.Root); err == nil {
		t.Fatal("reconciliation accepted a mutated project identity")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("authoritative backup was removed after configuration mutation: %v", err)
	}
	if before.Size() != after.Size() {
		t.Fatalf("authoritative backup size changed after rejected mutation: %d -> %d", before.Size(), after.Size())
	}
}

func TestCompiledProjectPolicyRejectsDeliveryAndPrivacyMutations(t *testing.T) {
	canonical := ProjectConfig{
		ServerURL:      compiledServerURL,
		OrganizationID: compiledOrganizationID,
		ProjectName:    compiledProjectName,
		EnabledTools: []string{
			model.ToolClaudeCode, model.ToolCodex, model.ToolCopilotCLI,
		},
		RetentionDays: compiledRetentionDays,
		RedactSecrets: true,
		AutoEnroll:    true,
		LocalStore:    true,
	}
	if err := validateCompiledProjectPolicy(canonical); err != nil {
		t.Fatalf("canonical compiled policy was rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProjectConfig)
	}{
		{name: "server", mutate: func(config *ProjectConfig) {
			config.ServerURL = "https://attacker.example.invalid"
		}},
		{name: "delivery-mode", mutate: func(config *ProjectConfig) {
			config.LocalStore = false
		}},
		{name: "automatic-enrollment", mutate: func(config *ProjectConfig) {
			config.AutoEnroll = false
		}},
		{name: "secret-redaction", mutate: func(config *ProjectConfig) {
			config.RedactSecrets = false
		}},
		{name: "custom-redaction", mutate: func(config *ProjectConfig) {
			config.RedactionPatterns = []string{"(?s).*"}
		}},
		{name: "retention", mutate: func(config *ProjectConfig) {
			config.RetentionDays--
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := canonical
			test.mutate(&mutated)
			if err := validateCompiledProjectPolicy(mutated); err == nil {
				t.Fatal("mutated compiled project policy was accepted")
			}
		})
	}
}
