package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/acme/prompt-audit-template/internal/model"
)

const (
	configDirectoryName = "prompt-audit"
	userConfigFileName  = "config.json"
	projectConfigPath   = ".devtools/project.json"
	profilesDirectory   = "profiles"

	compiledOrganizationID = "development"
	compiledProjectName    = "workspace"
	compiledServerURL      = "http://localhost:8080"
	compiledRetentionDays  = 365
)

var compiledProjectPolicyValidator = validateCompiledProjectPolicy

var ErrNotConfigured = errors.New("devtools has no identity and automatic enrollment is disabled; run setup")

type UserConfig struct {
	UserID          string `json:"user_id"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	ServerURL       string `json:"server_url"`
	OrganizationID  string `json:"organization_id,omitempty"`
	InstallationID  string `json:"installation_id,omitempty"`
	IdentitySource  string `json:"identity_source,omitempty"`
	EnrollmentState string `json:"enrollment_state,omitempty"`
	Token           string `json:"token"`
}

type ProjectConfig struct {
	ServerURL         string   `json:"server_url"`
	OrganizationID    string   `json:"organization_id"`
	ProjectName       string   `json:"project_name"`
	EnabledTools      []string `json:"enabled_tools"`
	RetentionDays     int      `json:"retention_days"`
	RedactSecrets     bool     `json:"redact_secrets"`
	RedactionPatterns []string `json:"redaction_patterns"`
	AutoEnroll        bool     `json:"auto_enroll"`
	// LocalStore enables an offline demo mode: captured prompts are written to a
	// JSONL file inside the repository instead of being enrolled and delivered to
	// a server. No network, credentials, or external queue are used. It is for
	// demonstrations only; prompts are stored in the working tree of each clone.
	LocalStore bool `json:"local_store,omitempty"`
}

func configDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv("PROMPT_AUDIT_CONFIG_DIR")); override != "" {
		if !filepath.IsAbs(override) {
			return "", errors.New("PROMPT_AUDIT_CONFIG_DIR must be an absolute path outside the repository")
		}
		return filepath.Clean(override), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(dir, configDirectoryName), nil
}

func validateExternalConfigDirectory(repositoryRoot string) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	root, err := resolvePathThroughExistingAncestor(repositoryRoot)
	if err != nil {
		return fmt.Errorf("resolve repository root for credential storage: %w", err)
	}
	dir, err = resolvePathThroughExistingAncestor(dir)
	if err != nil {
		return fmt.Errorf("resolve credential directory: %w", err)
	}
	relative, err := filepath.Rel(root, dir)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("devtools refuses to store credentials or its queue inside the repository")
	}
	return nil
}

func resolvePathThroughExistingAncestor(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	var missing []string
	for {
		resolved, err := evalAccessibleSymlinks(current, 0)
		if err == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Abs(resolved)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return absolute, nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func evalAccessibleSymlinks(path string, depth int) (string, error) {
	if depth > 64 {
		return "", errors.New("too many symbolic links in credential path")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	remainder = strings.TrimLeft(remainder, string(filepath.Separator))
	parts := []string{}
	if remainder != "" {
		parts = strings.Split(remainder, string(filepath.Separator))
	}
	current := volume
	if filepath.IsAbs(absolute) {
		current += string(filepath.Separator)
	}
	for index, part := range parts {
		candidate := filepath.Join(current, part)
		info, err := os.Lstat(candidate)
		if err != nil {
			// Managed sandboxes can deny metadata access to a parent while allowing
			// the explicitly shared descendant. Continue component-by-component so
			// symlinks/junctions inside the accessible tree are still resolved.
			if errors.Is(err, os.ErrPermission) {
				current = candidate
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = candidate
			continue
		}
		target, err := os.Readlink(candidate)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(candidate), target)
		}
		remaining := parts[index+1:]
		combined := target
		if len(remaining) > 0 {
			combined = filepath.Join(append([]string{target}, remaining...)...)
		}
		return evalAccessibleSymlinks(combined, depth+1)
	}
	return filepath.Clean(current), nil
}

func LoadUserConfig() (UserConfig, error) {
	dir, err := configDir()
	if err != nil {
		return UserConfig{}, err
	}
	return loadUserConfigAt(filepath.Join(dir, userConfigFileName))
}

func loadUserConfigAt(path string) (UserConfig, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return UserConfig{}, ErrNotConfigured
	} else if err != nil {
		return UserConfig{}, fmt.Errorf("inspect user configuration: %w", err)
	}
	root, err := configDir()
	if err != nil {
		return UserConfig{}, err
	}
	if err := validateDirectoryTree(root, filepath.Dir(path)); err != nil {
		return UserConfig{}, fmt.Errorf("validate user configuration path: %w", err)
	}
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return UserConfig{}, ErrNotConfigured
	}
	if err != nil {
		return UserConfig{}, fmt.Errorf("read user configuration: %w", err)
	}
	const maxUserConfigBytes = 128 * 1024
	b, readErr := io.ReadAll(io.LimitReader(file, maxUserConfigBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return UserConfig{}, fmt.Errorf("read user configuration: %w", readErr)
	}
	if closeErr != nil {
		return UserConfig{}, fmt.Errorf("close user configuration: %w", closeErr)
	}
	if len(b) > maxUserConfigBytes {
		return UserConfig{}, errors.New("user configuration exceeds 128 KiB")
	}
	if err := validateUniqueJSONKeys(b); err != nil {
		return UserConfig{}, errors.New("user configuration contains ambiguous or invalid JSON")
	}
	var cfg UserConfig
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return UserConfig{}, fmt.Errorf("decode user configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return UserConfig{}, errors.New("user configuration contains trailing JSON")
	}
	if cfg.UserID == "" || cfg.Name == "" || cfg.Email == "" || cfg.Token == "" {
		return UserConfig{}, ErrNotConfigured
	}
	canonicalServer, err := canonicalServerURL(cfg.ServerURL)
	if err != nil {
		return UserConfig{}, err
	}
	cfg.ServerURL = canonicalServer
	return cfg, nil
}

func SaveUserConfig(cfg UserConfig) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	return saveUserConfigAt(filepath.Join(dir, userConfigFileName), cfg)
}

func loadUserConfigForProject(project ProjectConfig) (UserConfig, string, error) {
	profile, err := projectProfileKey(project)
	if err != nil {
		return UserConfig{}, "", err
	}
	dir, err := configDir()
	if err != nil {
		return UserConfig{}, "", err
	}
	cfg, err := loadUserConfigAt(filepath.Join(dir, profilesDirectory, profile, userConfigFileName))
	if err == nil {
		if err := validateConfigForProject(cfg, project); err != nil {
			return UserConfig{}, "", err
		}
		return cfg, profile, nil
	}
	if !errors.Is(err, ErrNotConfigured) {
		return UserConfig{}, "", err
	}
	// Backward compatibility for users that completed setup with v0.1.0. New
	// automatic enrollments are always written to an isolated profile.
	legacy, legacyErr := LoadUserConfig()
	if legacyErr != nil {
		return UserConfig{}, profile, err
	}
	if err := validateConfigForProject(legacy, project); err != nil {
		return UserConfig{}, profile, ErrNotConfigured
	}
	return legacy, "", nil
}

func saveUserConfigForProject(project ProjectConfig, cfg UserConfig) (string, error) {
	profile, err := projectProfileKey(project)
	if err != nil {
		return "", err
	}
	cfg.ServerURL, err = canonicalServerURL(project.ServerURL)
	if err != nil {
		return "", err
	}
	cfg.OrganizationID = project.OrganizationID
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return profile, saveUserConfigAt(filepath.Join(dir, profilesDirectory, profile, userConfigFileName), cfg)
}

func saveUserConfigAt(path string, cfg UserConfig) error {
	canonicalServer, err := canonicalServerURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	cfg.ServerURL = canonicalServer
	if cfg.UserID == "" || cfg.Name == "" || cfg.Email == "" || cfg.Token == "" {
		return ErrNotConfigured
	}
	configRoot, err := configDir()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ensureDirectoryDurableUnder(configRoot, dir, 0o700); err != nil {
		return fmt.Errorf("create user configuration directory: %w", err)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode user configuration: %w", err)
	}
	f, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create user configuration: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Close(); err != nil {
		return fmt.Errorf("close empty user configuration: %w", err)
	}
	// On Windows, chmod alone does not remove inherited DACL entries. Apply the
	// full private ACL before any token or installation identity is written.
	f, err = openProtectedRegularFile(configRoot, tmp, os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open protected user configuration: %w", err)
	}
	if _, err = f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("write user configuration: %w", err)
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync user configuration: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close user configuration: %w", err)
	}
	// Replace only after the complete credential is durable. The platform helper
	// uses an atomic replacement, so a crash cannot truncate the only token copy.
	if err := replaceFile(tmp, path); err != nil {
		return fmt.Errorf("replace user configuration: %w", err)
	}
	return syncDirectory(dir)
}

func validateConfigForProject(cfg UserConfig, project ProjectConfig) error {
	configuredServer, configuredErr := canonicalServerURL(cfg.ServerURL)
	projectServer, projectErr := canonicalServerURL(project.ServerURL)
	if configuredErr != nil || projectErr != nil || configuredServer != projectServer {
		return errors.New("user and project server URLs do not match")
	}
	if cfg.OrganizationID == "" && project.AutoEnroll {
		return errors.New("legacy user configuration has no organization; automatic enrollment will create an isolated project profile")
	}
	if cfg.OrganizationID != "" && cfg.OrganizationID != project.OrganizationID {
		return errors.New("user and project organizations do not match")
	}
	return nil
}

func projectProfileKey(project ProjectConfig) (string, error) {
	server, err := canonicalServerURL(project.ServerURL)
	if err != nil {
		return "", err
	}
	organization := strings.TrimSpace(project.OrganizationID)
	if !validProjectOrganizationID(organization) {
		return "", errors.New("organization_id is invalid")
	}
	value := server + "\n" + organization
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:16]), nil
}

func (cfg UserConfig) enrolled() bool {
	if cfg.EnrollmentState == "" {
		// v0.1.0 did not persist a state field; a complete legacy credential is
		// already enrolled and must continue to work after upgrading.
		return cfg.UserID != "" && cfg.Token != ""
	}
	return cfg.EnrollmentState == "enrolled"
}

func loadProjectConfig(root string) (ProjectConfig, error) {
	path := filepath.Join(root, filepath.FromSlash(projectConfigPath))
	if err := validateDirectoryTree(root, filepath.Dir(path)); err != nil {
		return ProjectConfig{}, fmt.Errorf("validate project configuration path: %w", err)
	}
	file, err := openExistingRegularFile(path, os.O_RDONLY, 0)
	if err != nil {
		return ProjectConfig{}, fmt.Errorf("read project configuration: %w", err)
	}
	b, readErr := io.ReadAll(io.LimitReader(file, 256*1024+1))
	closeErr := file.Close()
	if readErr != nil {
		return ProjectConfig{}, fmt.Errorf("read project configuration: %w", readErr)
	}
	if closeErr != nil {
		return ProjectConfig{}, fmt.Errorf("close project configuration: %w", closeErr)
	}
	if len(b) > 256*1024 {
		return ProjectConfig{}, errors.New("project configuration exceeds 256 KiB")
	}
	if err := validateUniqueJSONKeys(b); err != nil {
		return ProjectConfig{}, errors.New("project configuration contains ambiguous or invalid JSON")
	}
	var cfg ProjectConfig
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return ProjectConfig{}, fmt.Errorf("decode project configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ProjectConfig{}, errors.New("project configuration contains trailing JSON")
	}
	cfg.ProjectName = strings.TrimSpace(cfg.ProjectName)
	cfg.OrganizationID = strings.TrimSpace(cfg.OrganizationID)
	if err := validateProjectConfig(cfg); err != nil {
		return ProjectConfig{}, err
	}
	canonicalServer, err := canonicalServerURL(cfg.ServerURL)
	if err != nil {
		return ProjectConfig{}, fmt.Errorf("project server URL: %w", err)
	}
	cfg.ServerURL = canonicalServer
	return cfg, nil
}

func validateProjectConfig(cfg ProjectConfig) error {
	if !validProjectText(cfg.ProjectName, 1, 255) {
		return errors.New("project_name must contain between 1 and 255 UTF-8 bytes")
	}
	if !validProjectOrganizationID(cfg.OrganizationID) {
		return errors.New("organization_id contains unsupported characters or exceeds 100 characters")
	}
	if cfg.ProjectName != compiledProjectName || cfg.OrganizationID != compiledOrganizationID {
		return errors.New("project identity does not match the identity compiled into this audit agent")
	}
	if cfg.RetentionDays < 1 || cfg.RetentionDays > 3650 {
		return errors.New("retention_days must be between 1 and 3650")
	}
	// An adapter this build does not know must never invalidate the file.
	// project.json is tracked, so a newer one arrives with an ordinary git pull
	// while the binary may still be the previous release — on Windows a running
	// background pass can hold the executable for minutes, so that mixed state
	// is real. Rejecting the whole file there made loadProjectConfig fail, which
	// fails DiscoverRepository, which makes capture exit 2 — and the provider
	// then REFUSES the worker's prompt. Not just the unknown adapter: Claude,
	// Codex and Copilot would all stop capturing until someone intervened.
	//
	// An unknown name cannot enable anything on its own: capture is gated per
	// tool by toolEnabled, and a build without that scanner simply never asks.
	// Ignoring it is therefore safe, and it is what lets a future adapter be
	// rolled out without a flag day.
	seen := make(map[string]struct{}, len(cfg.EnabledTools))
	for _, tool := range cfg.EnabledTools {
		if _, duplicate := seen[tool]; duplicate {
			return errors.New("enabled_tools contains a duplicate adapter")
		}
		seen[tool] = struct{}{}
	}
	// Removing one of the three is still refused: that is how capture would be
	// silenced, and it is the tampering this check exists to catch.
	for _, required := range []string{model.ToolClaudeCode, model.ToolCodex, model.ToolCopilotCLI} {
		if _, enabled := seen[required]; !enabled {
			return errors.New("enabled_tools must contain all three required prompt adapters")
		}
	}
	return compiledProjectPolicyValidator(cfg)
}

func validateCompiledProjectPolicy(cfg ProjectConfig) error {
	server, err := canonicalServerURL(cfg.ServerURL)
	if err != nil || server != compiledServerURL {
		return errors.New("server_url does not match the endpoint compiled into this audit agent")
	}
	if !cfg.LocalStore {
		return errors.New("local_store policy does not match this audit-agent build")
	}
	if !cfg.AutoEnroll {
		return errors.New("auto_enroll policy does not match this audit-agent build")
	}
	if !cfg.RedactSecrets || len(cfg.RedactionPatterns) != 0 {
		return errors.New("redaction policy does not match this audit-agent build")
	}
	if cfg.RetentionDays != compiledRetentionDays {
		return errors.New("retention policy does not match this audit-agent build")
	}
	return nil
}

func validProjectText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, '\x00') && len(value) >= minimum && len(value) <= maximum
}

func validProjectOrganizationID(value string) bool {
	if len(value) < 1 || len(value) > 100 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._-", character)) {
			continue
		}
		return false
	}
	return true
}

func (cfg ProjectConfig) toolEnabled(tool string) bool {
	for _, enabled := range cfg.EnabledTools {
		if enabled == tool {
			return true
		}
	}
	return false
}

func validateServerURL(raw string) error {
	_, err := canonicalServerURL(raw)
	return err
}

func canonicalServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("server_url must be an absolute URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("server_url must not contain credentials, query parameters, or fragments")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("server_url must use HTTPS")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if !strings.EqualFold(host, "localhost") && host != "127.0.0.1" && host != "::1" && !net.ParseIP(host).IsLoopback() {
			return "", errors.New("plain HTTP is allowed only for loopback development servers")
		}
	}
	u.Host = strings.ToLower(u.Host)
	// URL paths can be case-sensitive. Normalize only scheme/host and the
	// insignificant trailing slash so distinct API base paths remain isolated.
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func protectFile(authorityRoot, path string) error {
	_, err := protectFileIdentity(authorityRoot, path)
	return err
}

func protectFileIdentity(authorityRoot, path string) (os.FileInfo, error) {
	before, err := regularFileInfo(path)
	if err != nil {
		return nil, err
	}
	// On Windows this applies a protected cross-context ACL through a metadata
	// handle before any prompt-bearing file is opened for data access. On
	// POSIX, the helper is a no-op and chmod below remains authoritative.
	if err := protectPrivateFile(authorityRoot, path); err != nil {
		return nil, err
	}
	file, err := openExistingRegularFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	after, err := regularFileInfo(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(opened, after) {
		return nil, errors.New("refuse to protect a file that changed during validation")
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("refuse to protect a file whose identity changed")
	}
	return after, nil
}

// openProtectedRegularFile binds a data handle to the exact object whose ACL
// was protected. A path replacement after this identity check cannot redirect
// prompt bytes: writes continue through the already-open protected handle.
func openProtectedRegularFile(
	authorityRoot,
	path string,
	flag int,
	perm os.FileMode,
) (*os.File, error) {
	protected, err := protectFileIdentity(authorityRoot, path)
	if err != nil {
		return nil, err
	}
	file, err := openExistingRegularFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !os.SameFile(protected, opened) {
		_ = file.Close()
		return nil, errors.New("protected file changed before data access")
	}
	return file, nil
}
