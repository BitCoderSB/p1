package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateExternalConfigDirectoryRejectsSymlinkIntoRepository(t *testing.T) {
	repositoryRoot := t.TempDir()
	inside := filepath.Join(repositoryRoot, "versionable-credentials")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(outside, "config-link")
	if err := os.Symlink(inside, link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	// The leaf does not exist yet; validation must still resolve the existing
	// symlink/junction ancestor before MkdirAll follows it.
	t.Setenv("PROMPT_AUDIT_CONFIG_DIR", filepath.Join(link, "future-directory"))
	err := validateExternalConfigDirectory(repositoryRoot)
	if err == nil || !strings.Contains(err.Error(), "refuses to store credentials") {
		t.Fatalf("symlinked credential directory error = %v", err)
	}
}

func TestLoadUserConfigRejectsSymlinkAndUnknownFields(t *testing.T) {
	configRoot := useTestConfigDirectory(t)
	valid := UserConfig{
		UserID: "11111111-1111-4111-8111-111111111111", Name: "Worker",
		Email: "worker@example.invalid", ServerURL: "https://audit.example.invalid",
		Token: "pa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-config.json")
	if err := os.WriteFile(outside, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configRoot, userConfigFileName)
	requireFileSymlink(t, outside, configPath)
	if _, err := LoadUserConfig(); err == nil {
		t.Fatal("LoadUserConfig accepted a symbolic-link credential file")
	}

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	fields["assistant_response"] = "forbidden"
	encoded, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUserConfig(); err == nil {
		t.Fatal("LoadUserConfig accepted an unknown field")
	}
}
