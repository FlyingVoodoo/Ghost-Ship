package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*NodeManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	var m NodeManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	m.applyDefaults()
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &m, nil
}

func (m *NodeManifest) applyDefaults() {
	if m.Firewall.Backend == "" {
		m.Firewall.Backend = "ufw"
	}
	if m.Nomad.DataDir == "" {
		m.Nomad.DataDir = "/opt/nomad/data"
	}
	if m.Nomad.BindAddr == "" {
		m.Nomad.BindAddr = "0.0.0.0"
	}
	if m.Nomad.LogLevel == "" {
		m.Nomad.LogLevel = "INFO"
	}
	for i := range m.Services {
		if m.Services[i].Count == 0 {
			m.Services[i].Count = 1
		}
		if m.Services[i].MemoryMB == 0 {
			m.Services[i].MemoryMB = 128
		}
	}
	m.Firewall.AllowSSH = true
}

func (m *NodeManifest) validate() error {
	if m.Node.Role == "" {
		return fmt.Errorf("node.role is required (relay|exit)")
	}
	if m.Node.Role != RoleRelay && m.Node.Role != RoleExit {
		return fmt.Errorf("node.role must be 'relay' or 'exit', got %q", m.Node.Role)
	}
	if m.Node.Hostname == "" {
		return fmt.Errorf("node.hostname is required")
	}
	return nil
}
