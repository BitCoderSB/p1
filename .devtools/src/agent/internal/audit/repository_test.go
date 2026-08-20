package audit

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestValidateServerURLSecurityPolicy(t *testing.T) {
	valid := []string{
		"https://audit.example.invalid",
		"https://audit.example.invalid/base/path/",
		"http://localhost:8080",
		"http://127.0.0.1:9090",
		"http://[::1]:9090",
	}
	for _, raw := range valid {
		t.Run("valid_"+strings.NewReplacer(":", "_", "/", "_").Replace(raw), func(t *testing.T) {
			if err := validateServerURL(raw); err != nil {
				t.Errorf("validateServerURL(%q) = %v, want nil", raw, err)
			}
		})
	}

	invalid := []string{
		"",
		"audit.example.invalid",
		"/relative/path",
		"https:example.invalid",
		"ftp://audit.example.invalid",
		"http://audit.example.invalid",
		"https://user:password@audit.example.invalid",
		"https://audit.example.invalid?token=secret",
		"https://audit.example.invalid/#fragment",
	}
	for _, raw := range invalid {
		t.Run("invalid_"+strings.NewReplacer(":", "_", "/", "_").Replace(raw), func(t *testing.T) {
			if err := validateServerURL(raw); err == nil {
				t.Errorf("validateServerURL(%q) = nil, want rejection", raw)
			}
		})
	}
}

func TestSanitizeRemoteRemovesURLCredentials(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{
			name:   "HTTPS username and password",
			remote: " https://worker:access-token@example.invalid/acme/repo.git ",
			want:   "example.invalid/acme/repo",
		},
		{
			name:   "SSH user",
			remote: "ssh://git@example.invalid/acme/repo.git",
			want:   "example.invalid/acme/repo",
		},
		{
			name:   "SCP username removed",
			remote: "git@example.invalid:acme/repo.git",
			want:   "example.invalid/acme/repo",
		},
		{
			name:   "HTTPS query credentials",
			remote: "https://example.invalid/acme/repo.git?access_token=query-secret#fragment",
			want:   "example.invalid/acme/repo",
		},
		{
			name:   "SCP password credential",
			remote: "oauth2:scp-secret@example.invalid:acme/repo.git",
			want:   "example.invalid/acme/repo",
		},
		{
			name:   "SCP token-only credential",
			remote: "ghp_SUPERSECRET@example.invalid:acme/repo.git",
			want:   "example.invalid/acme/repo",
		},
		{
			name:   "blank",
			remote: "   ",
			want:   "",
		},
		{
			name:   "malformed URL",
			remote: "https://%zz",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRemote(tt.remote); got != tt.want {
				t.Fatalf("sanitizeRemote(%q) = %q, want %q", tt.remote, got, tt.want)
			}
		})
	}
}

func TestSanitizeRemoteNormalizesCommonCloneTransports(t *testing.T) {
	variants := []string{
		"https://github.com/acme/inventory.git",
		"ssh://git@github.com/acme/inventory.git",
		"git@github.com:acme/inventory.git",
		"https://token@GITHUB.COM/acme/inventory",
	}
	for _, remote := range variants {
		if got := sanitizeRemote(remote); got != "github.com/acme/inventory" {
			t.Errorf("sanitizeRemote(%q) = %q", remote, got)
		}
	}
}

func TestProjectProfileKeyPreservesCaseSensitiveServerPath(t *testing.T) {
	upper := ProjectConfig{ServerURL: "https://AUDIT.example.invalid/API/", OrganizationID: "acme"}
	lower := ProjectConfig{ServerURL: "https://audit.example.invalid/api", OrganizationID: "acme"}
	upperKey, err := projectProfileKey(upper)
	if err != nil {
		t.Fatal(err)
	}
	lowerKey, err := projectProfileKey(lower)
	if err != nil {
		t.Fatal(err)
	}
	if upperKey == lowerKey {
		t.Fatal("case-sensitive API paths shared one credential profile")
	}
	equivalent, err := projectProfileKey(ProjectConfig{
		ServerURL: "HTTPS://audit.example.invalid/API", OrganizationID: "acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	if equivalent != upperKey {
		t.Fatalf("scheme/host case or trailing slash changed profile: %q != %q", equivalent, upperKey)
	}
}

func TestDiscoverRepositoryFromNestedDirectoryWithSpaces(t *testing.T) {
	repository := newTestRepository(t, "https://audit.example.invalid", []string{
		model.ToolClaudeCode,
		model.ToolCopilotCLI,
	})

	got, err := DiscoverRepository(repository.Nested)
	if err != nil {
		t.Fatalf("DiscoverRepository() error = %v", err)
	}
	if !samePath(got.Root, repository.Root) {
		t.Errorf("Root = %q, want %q", got.Root, repository.Root)
	}
	if got.Name != compiledProjectName {
		t.Errorf("Name = %q, want %q", got.Name, compiledProjectName)
	}
	if got.Remote != "example.invalid/acme/repository" {
		t.Errorf("Remote = %q; credentials were not removed", got.Remote)
	}
	if got.Branch != repository.Branch {
		t.Errorf("Branch = %q, want %q", got.Branch, repository.Branch)
	}
	if got.CommitHash != repository.CommitHash {
		t.Errorf("CommitHash = %q, want %q", got.CommitHash, repository.CommitHash)
	}
	if !got.Project.toolEnabled(model.ToolClaudeCode) ||
		!got.Project.toolEnabled(model.ToolCopilotCLI) ||
		!got.Project.toolEnabled(model.ToolCodex) {
		t.Errorf("enabled tools were not loaded: %#v", got.Project.EnabledTools)
	}
}

func TestDiscoverRepositoryWithoutOriginKeepsIdentityAfterFirstCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required for repository integration tests")
	}
	root := filepath.Join(t.TempDir(), "empty repository")
	if err := os.MkdirAll(filepath.Join(root, ".devtools"), 0o755); err != nil {
		t.Fatal(err)
	}
	project := ProjectConfig{
		ServerURL:      "https://audit.example.invalid",
		OrganizationID: compiledOrganizationID,
		ProjectName:    compiledProjectName,
		EnabledTools: []string{
			model.ToolClaudeCode,
			model.ToolCodex,
			model.ToolCopilotCLI,
		},
		RetentionDays: 30,
		RedactSecrets: true,
	}
	encoded, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(projectConfigPath)), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init")
	runGit(t, root, "config", "user.name", "Prompt Audit Tests")
	runGit(t, root, "config", "user.email", "tests@example.invalid")

	before, err := DiscoverRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.Remote != stableLocalRepositoryRemote(project) {
		t.Fatalf("empty repository identity = %q", before.Remote)
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "first commit")
	after, err := DiscoverRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.Remote != before.Remote {
		t.Fatalf("repository identity changed after first commit: %q -> %q", before.Remote, after.Remote)
	}
}

func TestDiscoverRepositoryRefusesOutsideAndUnconfiguredRepositories(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "not a repository")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverRepository(outside); err == nil || !strings.Contains(err.Error(), "only inside a Git repository") {
		t.Fatalf("outside repository error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(outside, ".devtools")); !os.IsNotExist(err) {
		t.Fatalf("discovery modified an outside directory: %v", err)
	}
}

func TestDiscoverRepositoryDoesNotExposeRemoteCredentialsInErrors(t *testing.T) {
	repository := newTestRepository(t, "https://audit.example.invalid", []string{model.ToolClaudeCode})
	configPath := filepath.Join(repository.Root, filepath.FromSlash(projectConfigPath))
	if err := os.WriteFile(configPath, []byte(`{"server_url":"https://token:secret@example.invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := DiscoverRepository(repository.Nested)
	if err == nil {
		t.Fatal("DiscoverRepository() unexpectedly accepted invalid project configuration")
	}
	for _, secret := range []string{"token", "secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("DiscoverRepository() error leaked %q: %v", secret, err)
		}
	}
}
