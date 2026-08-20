package audit

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/acme/prompt-audit-template/internal/repositoryidentity"
)

type RepositoryInfo struct {
	Root       string
	Name       string
	Remote     string
	Branch     string
	CommitHash string
	Project    ProjectConfig
}

func DiscoverRepository(start string) (RepositoryInfo, error) {
	if strings.TrimSpace(start) == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return RepositoryInfo{}, fmt.Errorf("get working directory: %w", err)
		}
	}
	abs, err := filepath.Abs(start)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("resolve working directory: %w", err)
	}
	root, err := gitOutput(abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return RepositoryInfo{}, errors.New("capture is allowed only inside a Git repository")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("resolve repository root: %w", err)
	}
	project, err := loadProjectConfig(root)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf(
			"capture is disabled because .devtools/project.json could not be validated: %w",
			err,
		)
	}
	remote, _ := gitOutput(root, "config", "--get", "remote.origin.url")
	remote = sanitizeRemote(remote)
	if remote == "" {
		// Project metadata is versioned and therefore remains stable before and
		// after the first commit, across worktrees, and across local clones.
		remote = "local-project/" + project.OrganizationID + "/" + project.ProjectName
	}
	branch, _ := gitOutput(root, "symbolic-ref", "--quiet", "--short", "HEAD")
	commit, _ := gitOutput(root, "rev-parse", "--verify", "HEAD")
	name := project.ProjectName
	if name == "" {
		name = filepath.Base(root)
	}
	return RepositoryInfo{
		Root:       root,
		Name:       name,
		Remote:     remote,
		Branch:     branch,
		CommitHash: commit,
		Project:    project,
	}, nil
}

func gitOutput(dir string, args ...string) (string, error) {
	fullArgs := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", fullArgs...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	hideChildConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func sanitizeRemote(remote string) string {
	normalized, err := repositoryidentity.Normalize(remote)
	if err != nil {
		return ""
	}
	return normalized
}

func stableLocalRepositoryRemote(project ProjectConfig) string {
	return "local-project/" + project.OrganizationID + "/" + project.ProjectName
}

func repositoryRemoteForEvent(repo RepositoryInfo) string {
	if repo.Project.LocalStore {
		// Local registry identity must survive a legitimate origin URL change.
		// The versioned organization/project pair is immutable for this clone.
		return stableLocalRepositoryRemote(repo.Project)
	}
	return repo.Remote
}
