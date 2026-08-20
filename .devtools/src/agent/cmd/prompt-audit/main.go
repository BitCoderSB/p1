package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/acme/prompt-audit-template/agent/internal/audit"
)

var version = "0.1.0"
var sourceDigest = "development"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "setup":
		if err := runSetup(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "devtools setup:", err)
			os.Exit(1)
		}
	case "capture":
		// Network delivery is fail-open because Capture persists before sending.
		// A pre-durability failure exits 2 so tools that support blocking never
		// accept a prompt that was not recorded.
		result, err := runCapture(os.Args[2:])
		if errors.Is(err, audit.ErrNotUserPrompt) {
			os.Exit(0)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "devtools capture failed before durable storage:", err)
			os.Exit(2)
		}
		if result.Warning != "" {
			fmt.Fprintln(os.Stderr, "devtools capture warning:", result.Warning)
		}
		os.Exit(0)
	case "flush":
		flushed, remaining, rejected, err := audit.Flush()
		fmt.Printf("Enviados: %d; pendientes: %d; rechazados preservados: %d\n", flushed, remaining, rejected)
		if err != nil {
			fmt.Fprintln(os.Stderr, "devtools flush:", err)
			os.Exit(1)
		}
	case "status":
		if err := audit.Status(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "devtools status:", err)
			os.Exit(1)
		}
	case "log":
		workingDirectory, _ := os.Getwd()
		if err := audit.LocalLog(os.Stdout, workingDirectory); err != nil {
			fmt.Fprintln(os.Stderr, "devtools log:", err)
			os.Exit(1)
		}
	case "init":
		// One-time per-clone activation. History recovery is intentionally
		// separate so SessionStart has a bounded duration.
		workingDirectory, _ := os.Getwd()
		if err := audit.Init(os.Stdout, workingDirectory); err != nil {
			fmt.Fprintln(os.Stderr, "devtools init:", err)
			os.Exit(1)
		}
	case "activate":
		workingDirectory, _ := os.Getwd()
		if err := audit.Activate(os.Stdout, workingDirectory); err != nil {
			fmt.Fprintln(os.Stderr, "devtools activate:", err)
			os.Exit(1)
		}
	case "report":
		if err := runReport(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "devtools report:", err)
			os.Exit(1)
		}
	case "reconcile":
		// Publish and stage already-durable direct captures without scanning
		// provider histories.
		workingDirectory, _ := os.Getwd()
		if err := audit.ReconcileRegistry(workingDirectory); err != nil {
			fmt.Fprintln(os.Stderr, "devtools reconcile incomplete:", err)
			os.Exit(1)
		}
	case "stage-direct":
		// Commit-time fast path: stage only the public copies already written by
		// direct hooks. It never scans or waits for private-backup recovery.
		workingDirectory, _ := os.Getwd()
		if err := audit.StageDirectRegistry(workingDirectory); err != nil {
			fmt.Fprintln(os.Stderr, "devtools direct staging incomplete:", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "recover":
		workingDirectory, _ := os.Getwd()
		if err := audit.RecoverRegistry(workingDirectory); err != nil {
			fmt.Fprintln(os.Stderr, "devtools history recovery incomplete:", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "backfill":
		// Detached background recovery. Nobody reads this process's output or
		// exit status, so a partial pass is recorded in the health log and
		// retried later instead of being reported here.
		workingDirectory, _ := os.Getwd()
		audit.RunBackgroundBackfill(workingDirectory)
		os.Exit(0)
	case "version", "--version", "-version":
		fmt.Printf("%s source=%s\n", version, sourceDigest)
	default:
		usage()
		os.Exit(2)
	}
}

func runCapture(args []string) (audit.CaptureResult, error) {
	flags := flag.NewFlagSet("capture", flag.ContinueOnError)
	tool := flags.String("tool", "", "AI tool identifier")
	if err := flags.Parse(args); err != nil {
		return audit.CaptureResult{}, err
	}
	if *tool == "" {
		return audit.CaptureResult{}, errors.New("--tool is required")
	}
	return audit.Capture(*tool, os.Stdin)
}

func runReport(args []string) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	output := flags.String("output", "", "path for the HTML report (default .devtools/report.html)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	workingDirectory, _ := os.Getwd()
	path, err := audit.GenerateReport(workingDirectory, *output)
	if err != nil {
		return err
	}
	fmt.Println("Reporte generado:", path)
	fmt.Println("Ábrelo en tu navegador para revisar los prompts por usuario y chat.")
	return nil
}

func runSetup(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	options := audit.SetupOptions{}
	flags.StringVar(&options.Name, "name", "", "worker name")
	flags.StringVar(&options.Email, "email", "", "company email")
	flags.StringVar(&options.ServerURL, "server", "", "audit server URL")
	flags.StringVar(&options.RegistrationCode, "registration-code", "", "registration code")
	flags.StringVar(&options.OrganizationID, "organization", "", "organization identifier")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return audit.Setup(os.Stdin, os.Stdout, options)
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: setup <init|activate|setup|capture|flush|status|log|report|reconcile|stage-direct|recover|backfill|version> [options]")
}
