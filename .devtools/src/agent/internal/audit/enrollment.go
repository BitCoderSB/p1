package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

const (
	automaticEnrollmentTimeout = 700 * time.Millisecond
	pendingEnrollmentState     = "pending"
	enrolledEnrollmentState    = "enrolled"
)

func captureProfile(repo RepositoryInfo) (UserConfig, string, error) {
	if err := validateExternalConfigDirectory(repo.Root); err != nil {
		return UserConfig{}, "", err
	}
	cfg, profile, err := loadUserConfigForProject(repo.Project)
	if err == nil {
		return refreshPendingIdentity(repo, cfg, profile)
	}
	if !errors.Is(err, ErrNotConfigured) {
		return UserConfig{}, "", err
	}
	if !repo.Project.AutoEnroll {
		return UserConfig{}, "", ErrNotConfigured
	}
	return createPendingProfile(repo)
}

func refreshPendingIdentity(repo RepositoryInfo, cfg UserConfig, profile string) (UserConfig, string, error) {
	if cfg.enrolled() || profile == "" || !repo.Project.AutoEnroll {
		return cfg, profile, nil
	}
	name, email, source := automaticIdentity(repo.Root)
	// Device identity is already stable. Refresh only when Git now supplies a
	// stronger organizational hint (or when that Git identity itself changed).
	if source != "git" || (cfg.Name == name && cfg.Email == email && cfg.IdentitySource == source) {
		return cfg, profile, nil
	}
	newUserID, err := newUUID()
	if err != nil {
		return UserConfig{}, "", err
	}
	newInstallationID, err := newUUID()
	if err != nil {
		return UserConfig{}, "", err
	}
	newToken, err := newAgentToken()
	if err != nil {
		return UserConfig{}, "", err
	}
	queue, err := openQueueForProfile(profile)
	if err != nil {
		return UserConfig{}, "", err
	}
	result := cfg
	resultProfile := profile
	err = queue.withLock(func() error {
		current, currentProfile, err := loadUserConfigForProject(repo.Project)
		if err != nil {
			return err
		}
		if currentProfile != profile || current.enrolled() ||
			current.Token != cfg.Token || current.InstallationID != cfg.InstallationID {
			result = current
			resultProfile = currentProfile
			return nil
		}
		current.Name = name
		current.Email = email
		current.IdentitySource = source
		// An enrollment request for the previous identity may already be in
		// flight. Rotating all provisional material makes its completion fail the
		// compare-and-swap instead of marking stale identity data as enrolled.
		current.UserID = newUserID
		current.InstallationID = newInstallationID
		current.Token = newToken
		if _, err := saveUserConfigForProject(repo.Project, current); err != nil {
			return err
		}
		result = current
		return nil
	})
	return result, resultProfile, err
}

func createPendingProfile(repo RepositoryInfo) (UserConfig, string, error) {
	profile, err := projectProfileKey(repo.Project)
	if err != nil {
		return UserConfig{}, "", err
	}
	dir, err := configDir()
	if err != nil {
		return UserConfig{}, "", err
	}
	profileDir := filepath.Join(dir, profilesDirectory, profile)
	if err := ensureDirectoryDurableUnder(dir, profileDir, 0o700); err != nil {
		return UserConfig{}, "", fmt.Errorf("create enrollment profile: %w", err)
	}
	// Prepare candidate material before taking the inter-process lock. Only the
	// winning process persists it; the critical section stays short on Windows.
	name, email, source := automaticIdentity(repo.Root)
	userID, err := newUUID()
	if err != nil {
		return UserConfig{}, "", err
	}
	installationID, err := newUUID()
	if err != nil {
		return UserConfig{}, "", err
	}
	token, err := newAgentToken()
	if err != nil {
		return UserConfig{}, "", err
	}
	queue, err := openQueueForProfile(profile)
	if err != nil {
		return UserConfig{}, "", err
	}
	var result UserConfig
	err = queue.withLock(func() error {
		if cfg, _, loadErr := loadUserConfigForProject(repo.Project); loadErr == nil {
			result = cfg
			return nil
		} else if !errors.Is(loadErr, ErrNotConfigured) {
			return loadErr
		}
		result = UserConfig{
			UserID:          userID,
			Name:            name,
			Email:           email,
			ServerURL:       strings.TrimRight(repo.Project.ServerURL, "/"),
			OrganizationID:  repo.Project.OrganizationID,
			InstallationID:  installationID,
			IdentitySource:  source,
			EnrollmentState: pendingEnrollmentState,
			Token:           token,
		}
		_, saveErr := saveUserConfigForProject(repo.Project, result)
		return saveErr
	})
	if err != nil {
		return UserConfig{}, "", err
	}
	return result, profile, nil
}

func enrollProfile(repo RepositoryInfo, queue *Queue, cfg UserConfig) (UserConfig, error) {
	current, _, err := loadUserConfigForProject(repo.Project)
	if err != nil {
		return cfg, err
	}
	if current.enrolled() {
		return current, nil
	}
	// Another process may have created or replaced the pending profile after the
	// caller loaded it. Always enroll the credential that is current on disk.
	cfg = current
	if cfg.enrolled() {
		return cfg, nil
	}
	if !repo.Project.AutoEnroll {
		return UserConfig{}, ErrNotConfigured
	}
	response, err := Enroll(repo.Project.ServerURL, cfg.Token, EnrollmentRequest{
		Name:           cfg.Name,
		Email:          cfg.Email,
		OrganizationID: repo.Project.OrganizationID,
		InstallationID: cfg.InstallationID,
	}, automaticEnrollmentTimeout)
	if err != nil {
		return cfg, err
	}
	// Persist the canonical identity atomically with respect to new enqueues.
	// Older offline events need no O(n) rewrite: the authenticated API client
	// binds them to this canonical identity in memory when it sends them.
	cfg.UserID = response.UserID
	cfg.EnrollmentState = enrolledEnrollmentState
	return queue.completeEnrollmentIfCurrent(repo.Project, current, cfg)
}

func automaticIdentity(root string) (string, string, string) {
	name, _ := gitOutput(root, "config", "user.name")
	email, _ := gitOutput(root, "config", "user.email")
	name = strings.TrimSpace(name)
	if parsed, err := mail.ParseAddress(strings.TrimSpace(email)); err == nil && parsed.Address != "" {
		email = strings.ToLower(parsed.Address)
		if name == "" {
			name = strings.TrimSpace(parsed.Name)
		}
		if name == "" {
			name = strings.Split(email, "@")[0]
		}
		return name, email, "git"
	}

	accountName := "Developer"
	accountKey := "unknown"
	if account, err := user.Current(); err == nil {
		if strings.TrimSpace(account.Name) != "" {
			accountName = strings.TrimSpace(account.Name)
		} else if strings.TrimSpace(account.Username) != "" {
			accountName = strings.TrimSpace(account.Username)
		}
		accountKey = account.Username
	}
	hostname, _ := os.Hostname()
	sum := sha256.Sum256([]byte(strings.ToLower(accountKey) + "\n" + strings.ToLower(hostname)))
	return accountName, "device-" + hex.EncodeToString(sum[:8]) + "@prompt-audit.invalid", "device"
}

func newAgentToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("generate automatic enrollment token")
	}
	return "pa_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
