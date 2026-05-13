package provisioner

import (
	"fmt"
	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
	"log/slog"
)

func RunFullProvisioning(client *sshutil.SSHClient, m *config.NodeManifest) error {
	slog.Info("provisioning sequence initiated")

	slog.Info("executing system update", "command", "apt-get update")
	if _, err := client.Run("sudo apt-get update && sudo apt-get upgrade -y"); err != nil {
		return fmt.Errorf("system update failed: %w", err)
	}

	slog.Info("verifying environment", "check", "docker_presence")
	if _, err := client.Run("which docker"); err != nil {
		slog.Warn("docker not found, initiating installation")
		installCmd := "curl -fsSL https://get.docker.com | sh"
		if _, err := client.Run(installCmd); err != nil {
			return fmt.Errorf("docker installation failed: %w", err)
		}
	}

	slog.Info("configuring firewall and hardening")c
	if err := ApplyHardening(client, m.Firewall); err != nil {
		return fmt.Errorf("hardening stage failed: %w", err)
	}

	slog.Info("provisioning completed successfully")
	return nil
}
