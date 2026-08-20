package audit

import (
	"testing"

	"github.com/acme/prompt-audit-template/internal/model"
)

func TestLocalRepositoryIdentityMigrationSurvivesOriginChange(t *testing.T) {
	repository := newTestRepository(t, "http://localhost:8080", []string{model.ToolClaudeCode})
	enableTestLocalStore(t, repository)
	discovered, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("discover synthetic repository: %v", err)
	}
	const email = "origin-migration@example.invalid"
	userID := localUserID(email)
	legacy := sampleEvent("legacy-origin-event", "synthetic prompt captured before identity pinning")
	legacy.UserID = userID
	legacy.UserEmail = email
	legacy.RepositoryName = discovered.Name
	legacy.RepositoryRemote = discovered.Remote
	if err := writeLocalEvent(repository.Root, legacy); err != nil {
		t.Fatalf("write legacy synthetic event: %v", err)
	}

	runGit(t, repository.Root, "remote", "set-url", "origin", "https://example.invalid/new-owner/new-repository.git")
	afterChange, err := DiscoverRepository(repository.Root)
	if err != nil {
		t.Fatalf("rediscover repository after origin change: %v", err)
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatalf("migrate legacy repository identity after origin changed: %v", err)
	}
	second := sampleEvent("post-origin-event", "synthetic prompt captured after origin changed")
	second.UserID = userID
	second.UserEmail = email
	second.RepositoryName = afterChange.Name
	second.RepositoryRemote = repositoryRemoteForEvent(afterChange)
	if err := writeLocalEvent(repository.Root, second); err != nil {
		t.Fatalf("write post-origin synthetic event: %v", err)
	}
	if err := publishAllRegistryBackups(repository.Root); err != nil {
		t.Fatalf("publish after origin change: %v", err)
	}

	events, err := readAuthoritativeEventsForPublish(repository.Root, userID)
	if err != nil {
		t.Fatalf("read authoritative events after origin change: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("authoritative event count after origin change = %d, want 2", len(events))
	}
	stable := stableLocalRepositoryRemote(afterChange.Project)
	for _, event := range events {
		if event.RepositoryRemote != stable {
			t.Fatal("an event retained mutable origin metadata after migration")
		}
	}
}
