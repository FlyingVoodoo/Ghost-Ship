package provisioner

import (
	"testing"

	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/internal/mocks"
)

func TestApplyHardening_UFW_Success(t *testing.T) {
	mock := mocks.NewMockSSHRunner(map[string]string{
		"sudo ufw allow ssh":      "",
		"sudo ufw allow 8443":     "",
		"sudo ufw --force enable": "",
	})

	fw := config.FirewallConfig{
		Backend:    "ufw",
		AllowPorts: []int{8443},
		AllowSSH:   true,
	}

	if err := ApplyHardening(mock, fw); err != nil {
		t.Fatalf("ApplyHardening returned error: %v", err)
	}
}

func TestApplyHardening_UnsupportedBackend(t *testing.T) {
	mock := mocks.NewMockSSHRunner(nil)
	fw := config.FirewallConfig{Backend: "nftables"}
	if err := ApplyHardening(mock, fw); err == nil {
		t.Fatalf("expected error for unsupported backend, got nil")
	}
}

func TestRunFullProvisioning_DockerMissing_Installs(t *testing.T) {
	mock := mocks.NewMockSSHRunner(map[string]string{
		"apt-get update":                         "",
		"which docker":                           "", // simulate not found
		"curl -fsSL https://get.docker.com | sh": "installed",
		"sudo ufw allow ssh":                     "",
		"sudo ufw allow 22":                      "",
		"sudo ufw allow 443":                     "",
		"sudo ufw allow 8443":                    "",
		"sudo ufw --force enable":                "",
	})

	m := &config.NodeManifest{
		Firewall: config.FirewallConfig{
			Backend:    "ufw",
			AllowSSH:   true,
			AllowPorts: []int{22, 443, 8443},
		},
	}
	// firewall defaults will set AllowSSH true
	if err := RunFullProvisioning(mock, m); err != nil {
		t.Fatalf("RunFullProvisioning returned error: %v", err)
	}
}
