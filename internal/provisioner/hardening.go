package provisioner

import (
	"fmt"
	"log/slog"

	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

func ApplyHardening(client *sshutil.SSHClient, fw config.FirewallConfig) error {
	slog.Info("applying network hardening rules", "backend", fw.Backend)

	if fw.Backend != "ufw" {
		return fmt.Errorf("unsupported firewall backend: %s", fw.Backend)
	}

	if fw.AllowSSH {
		slog.Debug("firewall: allowing ssh access")
		if _, err := client.Run("sudo ufw allow ssh"); err != nil {
			return fmt.Errorf("failed to allow ssh: %w", err)
		}
	}

	for _, port := range fw.AllowPorts {
		slog.Info("firewall: opening custom port", "port", port)
		cmd := fmt.Sprintf("sudo ufw allow %d", port)
		if _, err := client.Run(cmd); err != nil {
			return fmt.Errorf("failed to allow port %d: %w", err)
		}
	}

	slog.Info("firewall: enabling ufw")
	if _, err := client.Run("sudo ufw --force enable"); err != nil {
		return fmt.Errorf("failed to enable ufw: %w", err)
	}

	return nil
}
