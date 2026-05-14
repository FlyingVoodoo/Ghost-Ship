package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/matvejefimovyh/ghost-ship/internal/audit"
	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/internal/extractor"
	"github.com/matvejefimovyh/ghost-ship/internal/provisioner"
	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

const banner = `
  ____ _                      _        ____  _     _        
 / ___| |__   ___  ___| |_     / ___|| |__ (_)_ __  
| |  _| '_ \ / _ \/ __| __|____\___ \| '_ \| | '_ \ 
| |_| | | | | (_) \__ \ |_|_____|___) | | | | | |_) |
 \____|_| |_|\___/|___/\__|    |____/|_| |_|_| .__/ 
                                             |_|    
   Velesys Infrastructure Engine | v0.1.0-alpha
`

func main() {
	fmt.Print(banner)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "land":
		{
			if len(os.Args) < 3 {
				fmt.Println("Usage: gs land <IP> [config]")
				os.Exit(1)
			}
			cmdLand(os.Args[2], os.Args[3:])
		}
	case "migrate":
		{
			cmdMigrate(os.Args[2:])
		}
	case "extract":
		{
			if len(os.Args) < 3 {
				fmt.Println("Usage: gs extract <config_file>")
				os.Exit(1)
			}
			cmdExtract(os.Args[2])
		}
	case "audit":
		{
			if len(os.Args) < 3 {
				fmt.Println("Usage: gs audit <IP>")
				os.Exit(1)
			}
			cmdAudit(os.Args[2])
		}
	case "status":
		{
			if len(os.Args) < 3 {
				fmt.Println("Usage: gs status <IP>")
				os.Exit(1)
			}
			cmdStatus(os.Args[2])
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`
Available commands:
  land <IP> [config]      - Provision a fresh VPS (Full hardening + Docker + Nomad)
  extract <config>        - Extract system state for migration
  migrate <from> <to>     - Migrate infrastructure from one server to another
  audit <IP>              - Run comprehensive security audit
  status <IP>             - Check node status

Examples:
  gs land 192.168.1.100 configs/relay-ru.yaml
  gs extract configs/relay-ru.yaml
  gs migrate --from 192.168.1.100 --to 192.168.1.101
  gs audit 192.168.1.100
  gs status 192.168.1.100
`)
}

func cmdLand(ip string, args []string) {
	slog.Info("Starting land sequence", "target_ip", ip)

	configFile := "configs/example-node.yaml"
	if len(args) > 0 {
		configFile = args[0]
	}

	// Load configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// Connect to server
	client, err := sshutil.NewSSHClient("root", ip, 22, os.Getenv("SSH_KEY"))
	if err != nil {
		slog.Error("SSH connection failed", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	// Run full provisioning sequence
	if err := provisioner.RunFullProvisioning(client, cfg); err != nil {
		slog.Error("Provisioning failed", "error", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ Landing sequence completed successfully!")
	fmt.Println("✓ Server is ready for deployment")
}

func cmdExtract(configFile string) {
	slog.Info("Starting system state extraction", "config", configFile)

	// Load configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// Connect to server
	client, err := sshutil.NewSSHClient("root", cfg.Node.IP, 22, os.Getenv("SSH_KEY"))
	if err != nil {
		slog.Error("SSH connection failed", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	// Extract system state
	state, err := extractor.ExtractSystemState(client, cfg)
	if err != nil {
		slog.Error("Extraction failed", "error", err)
		os.Exit(1)
	}

	// Validate integrity
	if err := extractor.ValidateState(state); err != nil {
		slog.Error("State validation failed", "error", err)
		os.Exit(1)
	}

	// Pack into encrypted stream
	stream, err := extractor.PackSystemState(state)
	if err != nil {
		slog.Error("Packing state failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ System state extracted and encrypted\n")
	fmt.Printf("  Databases: %d\n", len(state.Databases))
	fmt.Printf("  Certificates: %d\n", len(state.Certificates))
	fmt.Printf("  Original size: %.2f MB\n", float64(stream.Size)/1024/1024)
	fmt.Printf("  Encrypted size: %.2f MB\n", float64(len(stream.Data))/1024/1024)
	fmt.Printf("  Compression ratio: %.1f%%\n", float64(len(stream.Data))/float64(stream.Size)*100)
}

func cmdMigrate(args []string) {
	if len(args) < 4 {
		fmt.Println("Usage: gs migrate --from <source_ip> --to <target_ip> [--config config.yaml]")
		os.Exit(1)
	}

	sourceIP := ""
	targetIP := ""
	configFile := "configs/example-node.yaml"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--from":
			if i+1 < len(args) {
				sourceIP = args[i+1]
				i++
			}
		case "--to":
			if i+1 < len(args) {
				targetIP = args[i+1]
				i++
			}
		case "--config":
			if i+1 < len(args) {
				configFile = args[i+1]
				i++
			}
		}
	}

	if sourceIP == "" || targetIP == "" {
		fmt.Println("Error: --from and --to are required")
		os.Exit(1)
	}

	slog.Info("starting migration", "from", sourceIP, "to", targetIP)

	cfg, err := config.Load(configFile)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Phase 1: Extracting state from source ===\n")
	sourceClient, err := sshutil.NewSSHClient("root", sourceIP, 22, os.Getenv("SSH_KEY"))
	if err != nil {
		slog.Error("SSH connection to source failed", "error", err)
		os.Exit(1)
	}
	defer sourceClient.Close()

	state, err := extractor.ExtractSystemState(sourceClient, cfg)
	if err != nil {
		slog.Error("State extraction failed", "error", err)
		os.Exit(1)
	}

	if err := extractor.ValidateState(state); err != nil {
		slog.Error("State validation failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Phase 2: Provisioning target server ===\n")
	targetClient, err := sshutil.NewSSHClient("root", targetIP, 22, os.Getenv("SSH_KEY"))
	if err != nil {
		slog.Error("SSH connection to target failed", "error", err)
		os.Exit(1)
	}
	defer targetClient.Close()

	if err := provisioner.RunFullProvisioning(targetClient, cfg); err != nil {
		slog.Error("Target provisioning failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Phase 3: Restoring state to target ===\n")

	if err := extractor.RestoreSystemState(targetClient, state); err != nil {
		slog.Error("State restoration failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ Migration completed successfully!\n")
	fmt.Printf("  Source: %s\n", sourceIP)
	fmt.Printf("  Target: %s\n", targetIP)
	fmt.Printf("  Databases migrated: %d\n", len(state.Databases))
	fmt.Printf("  Certificates migrated: %d\n", len(state.Certificates))
}

func cmdStatus(ip string) {
	fmt.Printf("Checking status of %s\n", ip)
	fmt.Println("Status command - not yet implemented")
}

func cmdAudit(ip string) {
	slog.Info("Starting security audit", "target_ip", ip)

	client, err := sshutil.NewSSHClient("root", ip, 22, os.Getenv("SSH_KEY"))
	if err != nil {
		slog.Error("SSH connection failed", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	report, err := audit.RunSecurityAudit(client, nil)
	if err != nil {
		slog.Error("Audit failed", "error", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Security Audit Report ===\n")
	fmt.Printf("Hostname: %s\n", report.Hostname)
	fmt.Printf("Timestamp: %d\n\n", report.Timestamp)

	fmt.Printf("System Security: %d checks\n", len(report.SystemChecks))
	fmt.Printf("Docker Security: %d checks\n", len(report.DockerChecks))
	fmt.Printf("Nomad Security: %d checks\n", len(report.NomadChecks))

	allAlerts := append(append(report.SystemChecks, report.DockerChecks...), report.NomadChecks...)
	if len(allAlerts) == 0 {
		fmt.Println("\n✓ All checks passed!")
	} else {
		fmt.Printf("\nAlerts: %d (Critical: %d, Warnings: %d, Passed: %d)\n",
			len(allAlerts), report.CriticalCount, report.WarningCount, report.PassedCount)
		for _, alert := range allAlerts {
			fmt.Printf("  %s (%s): %s\n", alert.Level, alert.Component, alert.Issue)
		}
	}
}
