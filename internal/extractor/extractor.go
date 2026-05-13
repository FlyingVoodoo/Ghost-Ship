package extractor

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

// SystemState holds all system information for migration
type SystemState struct {
	Hostname      string
	Location      config.Location
	Role          config.Role
	Timestamp     int64
	SystemInfo    map[string]string
	Certificates  map[string][]byte
	Databases     map[string][]byte
	Configs       map[string][]byte
	SSHPublicKeys map[string][]byte
}

// ExtractSystemState gathers all system state from the target server
func ExtractSystemState(client *sshutil.SSHClient, manifest *config.NodeManifest) (*SystemState, error) {
	slog.Info("starting system state extraction", "node", manifest.Node.Hostname)

	state := &SystemState{
		Hostname:      manifest.Node.Hostname,
		Location:      manifest.Node.Location,
		Role:          manifest.Node.Role,
		SystemInfo:    make(map[string]string),
		Certificates:  make(map[string][]byte),
		Databases:     make(map[string][]byte),
		Configs:       make(map[string][]byte),
		SSHPublicKeys: make(map[string][]byte),
	}

	if err := extractSystemInfo(client, state); err != nil {
		slog.Warn("failed to extract system info", "error", err)
	}

	if err := extractCertificates(client, state); err != nil {
		slog.Warn("partial failure extracting certificates", "error", err)
	}

	if err := extractDatabases(client, state); err != nil {
		slog.Warn("partial failure extracting databases", "error", err)
	}

	if err := extractConfigs(client, state); err != nil {
		slog.Warn("partial failure extracting configs", "error", err)
	}

	if err := extractSSHKeys(client, state); err != nil {
		slog.Warn("partial failure extracting ssh keys", "error", err)
	}

	slog.Info("system state extraction completed",
		"certs", len(state.Certificates),
		"databases", len(state.Databases),
		"configs", len(state.Configs),
	)

	return state, nil
}

func extractSystemInfo(client *sshutil.SSHClient, state *SystemState) error {
	slog.Debug("extracting system information")

	items := []struct {
		key string
		cmd string
	}{
		{"os_version", "cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2"},
		{"hostname", "hostname"},
		{"docker_version", "docker --version 2>/dev/null || echo 'not installed'"},
		{"total_memory", "free -h | awk 'NR==2 {print $2}'"},
	}

	for _, item := range items {
		if out, err := client.Run(item.cmd); err == nil {
			state.SystemInfo[item.key] = out
		}
	}

	return nil
}

func extractCertificates(client *sshutil.SSHClient, state *SystemState) error {
	certs, err := ExtractCertificates(client)
	if err != nil {
		return fmt.Errorf("extract certificates failed: %w", err)
	}

	state.Certificates = certs
	slog.Debug("certificates extracted", "count", len(certs))

	if xrayConfig, err := ExtractXrayConfig(client); err == nil && len(xrayConfig) > 0 {
		state.Configs["xray.json"] = xrayConfig
		slog.Debug("xray config extracted")
	}

	return nil
}

func extractDatabases(client *sshutil.SSHClient, state *SystemState) error {
	commonPaths := []string{
		"/opt/3x-ui/db/x-ui.db",
		"/opt/x-ui/db/x-ui.db",
		"/app/db/x-ui.db",
		"/var/lib/xui/x-ui.db",
	}

	extractedCount := 0
	for _, dbPath := range commonPaths {
		data, err := ExtractDatabase(client, dbPath)
		if err != nil {
			continue
		}

		if len(data) > 0 {
			state.Databases[filepath.Base(dbPath)] = data
			extractedCount++
			slog.Info("database extracted", "path", dbPath, "size_kb", len(data)/1024)
		}
	}

	if extractedCount == 0 {
		slog.Warn("no databases found in standard locations")
	}

	return nil
}

func extractConfigs(client *sshutil.SSHClient, state *SystemState) error {
	configPaths := map[string]string{
		"docker_config":   "/etc/docker/daemon.json",
		"nomad_config":    "/etc/nomad.d/nomad.hcl",
		"fail2ban_config": "/etc/fail2ban/jail.local",
		"ufw_rules":       "/etc/ufw/rules.v4",
	}

	for name, path := range configPaths {
		if out, err := client.Run(fmt.Sprintf("sudo cat %s 2>/dev/null || echo '[NOT_FOUND]'", path)); err == nil && out != "[NOT_FOUND]" {
			state.Configs[name] = []byte(out)
		}
	}

	return nil
}

func extractSSHKeys(client *sshutil.SSHClient, state *SystemState) error {
	keys := []struct {
		name string
		cmd  string
	}{
		{"root_authorized", "sudo cat /root/.ssh/authorized_keys 2>/dev/null || echo '[NOT_FOUND]'"},
		{"user_pubkey", "cat ~/.ssh/id_rsa.pub 2>/dev/null || echo '[NOT_FOUND]'"},
	}

	for _, k := range keys {
		if out, err := client.Run(k.cmd); err == nil && out != "[NOT_FOUND]" {
			state.SSHPublicKeys[k.name] = []byte(out)
		}
	}

	return nil
}

// ValidateState checks integrity of extracted state before transmission
func ValidateState(state *SystemState) error {
	if state.Hostname == "" {
		return fmt.Errorf("hostname is empty")
	}

	if len(state.Databases) == 0 {
		slog.Warn("no databases were extracted - migration might be incomplete")
	}

	if len(state.Certificates) == 0 {
		slog.Warn("no certificates were extracted")
	}

	slog.Info("state validation completed", "databases", len(state.Databases), "certificates", len(state.Certificates))
	return nil
}
