package audit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/acme/prompt-audit-template/internal/model"
)

type SetupOptions struct {
	Name             string
	Email            string
	ServerURL        string
	RegistrationCode string
	OrganizationID   string
}

func Setup(in io.Reader, out io.Writer, options SetupOptions) error {
	reader := bufio.NewReader(in)
	workingDirectory, _ := os.Getwd()
	repo, err := DiscoverRepository(workingDirectory)
	if err != nil {
		return err
	}
	if err := validateExternalConfigDirectory(repo.Root); err != nil {
		return err
	}
	if existing, _, loadErr := loadUserConfigForProject(repo.Project); loadErr == nil && existing.enrolled() {
		_, _ = fmt.Fprintln(out, "Registro ya configurado fuera del repositorio; no se emitió otro token.")
		return nil
	} else if loadErr != nil && !errors.Is(loadErr, ErrNotConfigured) {
		return loadErr
	}
	gitName, _ := gitOutput(workingDirectory, "config", "user.name")
	gitEmail, _ := gitOutput(workingDirectory, "config", "user.email")
	if options.OrganizationID == "" {
		options.OrganizationID = repo.Project.OrganizationID
	}
	if options.ServerURL == "" {
		options.ServerURL = repo.Project.ServerURL
	}
	if options.Name, err = ask(reader, out, "Nombre", options.Name, gitName, false); err != nil {
		return err
	}
	if options.Email, err = ask(reader, out, "Correo empresarial", options.Email, gitEmail, false); err != nil {
		return err
	}
	if options.ServerURL, err = ask(reader, out, "URL del servidor", options.ServerURL, "", false); err != nil {
		return err
	}
	if options.RegistrationCode, err = ask(reader, out, "Token o código de registro", options.RegistrationCode, "", true); err != nil {
		return err
	}
	if strings.TrimSpace(options.OrganizationID) == "" {
		return errors.New("organization_id is missing from the project configuration")
	}
	if strings.TrimSpace(options.OrganizationID) != repo.Project.OrganizationID {
		return errors.New("the setup organization must match .devtools/project.json")
	}
	canonicalServer, err := canonicalServerURL(options.ServerURL)
	if err != nil {
		return err
	}
	if canonicalServer != repo.Project.ServerURL {
		return errors.New("the setup server must match .devtools/project.json")
	}
	options.ServerURL = canonicalServer
	response, err := Register(options.ServerURL, model.RegistrationRequest{
		Name:             strings.TrimSpace(options.Name),
		Email:            strings.TrimSpace(options.Email),
		OrganizationID:   strings.TrimSpace(options.OrganizationID),
		RegistrationCode: options.RegistrationCode,
	})
	if err != nil {
		return err
	}
	installationID, err := newUUID()
	if err != nil {
		return err
	}
	profile, err := projectProfileKey(repo.Project)
	if err != nil {
		return err
	}
	queue, err := openQueueForProfile(profile)
	if err != nil {
		return err
	}
	// A worker can choose managed setup after automatic enrollment was pending
	// offline. Activate the manual credential atomically with new enqueues; old
	// events are bound to this identity in memory when they are transmitted.
	if err := queue.RebindIdentityAndSave(repo.Project, UserConfig{
		UserID:          response.UserID,
		Name:            strings.TrimSpace(options.Name),
		Email:           strings.TrimSpace(options.Email),
		ServerURL:       strings.TrimRight(options.ServerURL, "/"),
		OrganizationID:  repo.Project.OrganizationID,
		InstallationID:  installationID,
		IdentitySource:  "manual",
		EnrollmentState: "enrolled",
		Token:           response.Token,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "Registro completado. El token se guardó fuera del repositorio.")
	return nil
}

func ask(reader *bufio.Reader, out io.Writer, label, provided, fallback string, secret bool) (string, error) {
	if strings.TrimSpace(provided) != "" {
		return strings.TrimSpace(provided), nil
	}
	defaultHint := ""
	if fallback != "" && !secret {
		defaultHint = " [" + fallback + "]"
	}
	_, _ = fmt.Fprintf(out, "%s%s: ", label, defaultHint)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = strings.TrimSpace(fallback)
	}
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return value, nil
}
