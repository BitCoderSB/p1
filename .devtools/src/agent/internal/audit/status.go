package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/acme/prompt-audit-template/internal/model"
)

// capturedToolSummary makes a silent adapter obvious. A tool with zero prompts,
// or whose last prompt is old while the others are current, is the signature of
// a hook that never ran — the failure this project most needs to notice.
func capturedToolSummary(events []model.Event) string {
	latest := map[string]time.Time{}
	counts := map[string]int{}
	for _, event := range events {
		counts[event.Tool]++
		if event.Timestamp.After(latest[event.Tool]) {
			latest[event.Tool] = event.Timestamp
		}
	}
	tools := []string{
		model.ToolClaudeCode, model.ToolCodex,
		model.ToolCopilotCLI, model.ToolAntigravity,
	}
	sort.Strings(tools)
	var builder strings.Builder
	for _, tool := range tools {
		builder.WriteString("  ")
		builder.WriteString(tool)
		builder.WriteString(": ")
		if counts[tool] == 0 {
			builder.WriteString("sin prompts registrados\n")
			continue
		}
		fmt.Fprintf(&builder, "%d (último %s)\n", counts[tool], latest[tool].UTC().Format(time.RFC3339))
	}
	return "Por herramienta:\n" + builder.String()
}

func Status(out io.Writer) error {
	var cfg UserConfig
	var queue *Queue
	profile := ""
	workingDirectory, _ := os.Getwd()
	repo, repositoryErr := DiscoverRepository(workingDirectory)
	if repositoryErr != nil {
		if _, gitErr := gitOutput(workingDirectory, "rev-parse", "--show-toplevel"); gitErr == nil {
			return fmt.Errorf("repository prompt monitoring configuration is invalid: %w", repositoryErr)
		}
	} else {
		if runtimeErr := verifyInstalledProviderRuntimes(repo); runtimeErr != nil {
			return fmt.Errorf("provider runtime validation failed: %w", runtimeErr)
		}
		// status is the explicit diagnostic an administrator runs, so it repairs
		// what it can and then reports every remaining degradation instead of
		// stopping at the first one. Unlike SessionStart it may be loud.
		repaired, configErr := ensureProviderCaptureConfiguration(repo)
		if repo.Project.LocalStore {
			// status is a health check that must stay fast, so recovery runs
			// detached rather than inline. It still guarantees the sweep is
			// triggered on a machine whose Codex hooks were never approved.
			scheduleBackgroundBackfill(repo.Root)
			var statusProblems []error
			if repaired {
				if _, writeErr := fmt.Fprintln(out, "Aviso: se restauró la configuración canónica de los hooks de captura."); writeErr != nil {
					return writeErr
				}
			}
			if configErr != nil {
				recordLocalHealth(repo.Root, "status: a provider prompt hook could not be restored")
				statusProblems = append(statusProblems, fmt.Errorf(
					"provider prompt hooks are degraded: %w",
					configErr,
				))
				if _, writeErr := fmt.Fprintln(out, "Advertencia: un hook de captura no pudo restaurarse; la recuperación en segundo plano sigue activa."); writeErr != nil {
					return writeErr
				}
			}
			if hookErr := ensurePreCommitHook(repo.Root); hookErr != nil {
				recordLocalHealth(repo.Root, "status failed: pre-commit delivery hook is unavailable")
				statusProblems = append(statusProblems, fmt.Errorf(
					"pre-commit delivery hook is unavailable: %w",
					hookErr,
				))
				if _, writeErr := fmt.Fprintln(out, "Advertencia: el hook de entrega pre-commit no está activo; los prompts quedan en el respaldo privado hasta repararlo."); writeErr != nil {
					return writeErr
				}
			}
			if absorbed, absorbErr := absorbSpooledEvents(repo.Root); absorbErr != nil {
				statusProblems = append(statusProblems, absorbErr)
			} else if absorbed > 0 {
				if _, writeErr := fmt.Fprintf(out, "Prompts en cola integrados al respaldo: %d\n", absorbed); writeErr != nil {
					return writeErr
				}
			}
			if publishErr := publishAllRegistryBackups(repo.Root); publishErr != nil {
				return fmt.Errorf("publish prompt registry: %w", publishErr)
			}
			events, readErr := readRegistryEvents(repo.Root)
			if readErr != nil {
				return readErr
			}
			_, writeErr := fmt.Fprintf(out, "Modo: registro local (sin servidor)\nProyecto: %s\nCarpeta: %s\nPrompts registrados: %d\nÚltima recuperación automática: %s\n%sUsa 'setup log' o 'setup report' para verlos.\n",
				repo.Name,
				registryDir(repo.Root),
				len(events),
				lastBackfillDescription(repo.Root),
				capturedToolSummary(events),
			)
			if writeErr != nil {
				statusProblems = append(statusProblems, writeErr)
			}
			// Everything the agent chose not to fail on ends up here. Showing it
			// is what turns "degrade quietly" into something an administrator can
			// actually notice.
			if health := summarizeLocalHealth(repo.Root); health.Total > 0 {
				if _, err := fmt.Fprintf(
					out,
					"\nIncidencias registradas: %d (últimas %d)\n",
					health.Total,
					len(health.Recent),
				); err != nil {
					statusProblems = append(statusProblems, err)
				}
				for _, entry := range health.Recent {
					if _, err := fmt.Fprintf(out, "  %s\n", entry); err != nil {
						statusProblems = append(statusProblems, err)
						break
					}
				}
			}
			return errors.Join(statusProblems...)
		}
		if configErr != nil {
			recordLocalHealth(repo.Root, "status failed: provider prompt hooks are unavailable")
			return fmt.Errorf("provider prompt hooks are unavailable: %w", configErr)
		}
		if err := validateExternalConfigDirectory(repo.Root); err != nil {
			return err
		}
		if profileCfg, projectProfile, profileErr := loadUserConfigForProject(repo.Project); profileErr == nil {
			cfg = profileCfg
			profile = projectProfile
			queue, profileErr = openQueueForProfile(projectProfile)
			if profileErr != nil {
				return profileErr
			}
		} else if !errors.Is(profileErr, ErrNotConfigured) {
			return profileErr
		}
	}
	if queue == nil {
		var err error
		cfg, err = LoadUserConfig()
		if err != nil {
			return err
		}
		queue, err = OpenQueue()
		if err != nil {
			return err
		}
	}
	pending, err := queue.Count()
	if err != nil {
		return err
	}
	rejected, err := queue.RejectedCount()
	if err != nil {
		return err
	}
	state := "pendiente de enrolamiento"
	if cfg.enrolled() {
		state = "enrolado"
	}
	legacyPending := 0
	legacyRejected := 0
	if profile != "" {
		legacyQueue, openErr := OpenQueue()
		if openErr != nil {
			return openErr
		}
		if legacyPending, err = legacyQueue.Count(); err != nil {
			return err
		}
		if legacyRejected, err = legacyQueue.RejectedCount(); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(out, "Usuario: %s <%s>\nID: %s\nServidor: %s\nEstado: %s\nToken: configurado (oculto)\nEventos pendientes: %d\nEventos rechazados preservados: %d\nEventos heredados pendientes: %d\nEventos heredados rechazados: %d\n",
		cfg.Name, cfg.Email, cfg.UserID, cfg.ServerURL, state, pending, rejected, legacyPending, legacyRejected)
	return err
}
