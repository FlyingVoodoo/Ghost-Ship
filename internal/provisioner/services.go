package provisioner

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

const composeProjectDir = "/opt/ghost-ship/services"
const composeFileName = "docker-compose.yml"

func DeployServices(client sshutil.SSHRunner, services []config.ServiceSpec) error {
	if len(services) == 0 {
		slog.Info("no services declared in manifest")
		return nil
	}

	composeYAML, scaleArgs, err := buildComposeProject(services)
	if err != nil {
		return err
	}

	if _, err := client.Run(fmt.Sprintf("mkdir -p %s", composeProjectDir)); err != nil {
		return fmt.Errorf("failed to create compose project dir: %w", err)
	}

	composePath := fmt.Sprintf("%s/%s", composeProjectDir, composeFileName)
	currentCompose, err := readRemoteFile(client, composePath)
	if err != nil {
		return fmt.Errorf("failed to inspect existing docker compose file: %w", err)
	}

	if strings.TrimSpace(currentCompose) != strings.TrimSpace(composeYAML) {
		writeCmd := fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF", composePath, composeYAML)
		if _, err := client.Run(writeCmd); err != nil {
			return fmt.Errorf("failed to write docker compose file: %w", err)
		}
		slog.Info("compose project updated", "path", composePath)
	} else {
		slog.Info("compose project already up to date", "path", composePath)
	}

	upCmd := fmt.Sprintf("cd %s && docker compose up -d --pull always --remove-orphans", composeProjectDir)
	if len(scaleArgs) > 0 {
		upCmd = upCmd + " " + strings.Join(scaleArgs, " ")
	}

	if _, err := client.Run(upCmd); err != nil {
		return fmt.Errorf("failed to start services with docker compose: %w", err)
	}

	slog.Info("services deployed", "count", len(services), "project", composeProjectDir)
	return nil
}

func readRemoteFile(client sshutil.SSHRunner, remotePath string) (string, error) {
	out, err := client.Run(fmt.Sprintf("test -f %s && cat %s || true", remotePath, remotePath))
	if err != nil {
		return "", err
	}
	return out, nil
}

func buildComposeProject(services []config.ServiceSpec) (string, []string, error) {
	var builder strings.Builder
	builder.WriteString("version: '3.9'\n")
	builder.WriteString("services:\n")

	seen := make(map[string]struct{}, len(services))
	scaleArgs := make([]string, 0)

	for _, service := range services {
		if service.Name == "" {
			return "", nil, fmt.Errorf("service name is required")
		}
		if service.Image == "" {
			return "", nil, fmt.Errorf("service %q image is required", service.Name)
		}
		if _, exists := seen[service.Name]; exists {
			return "", nil, fmt.Errorf("duplicate service name %q", service.Name)
		}
		seen[service.Name] = struct{}{}

		count := service.Count
		if count < 1 {
			count = 1
		}
		if count > 1 && len(service.Ports) > 0 {
			return "", nil, fmt.Errorf("service %q cannot use ports while count > 1 with docker compose scaling", service.Name)
		}
		if count > 1 {
			scaleArgs = append(scaleArgs, fmt.Sprintf("--scale %s=%d", service.Name, count))
		}

		writeComposeService(&builder, service)
	}

	sort.Strings(scaleArgs)
	return builder.String(), scaleArgs, nil
}

func writeComposeService(builder *strings.Builder, service config.ServiceSpec) {
	builder.WriteString(fmt.Sprintf("  %s:\n", service.Name))
	builder.WriteString(fmt.Sprintf("    image: %s\n", service.Image))
	builder.WriteString("    restart: unless-stopped\n")

	if service.MemoryMB > 0 {
		builder.WriteString(fmt.Sprintf("    mem_limit: %dm\n", service.MemoryMB))
	}

	if len(service.Env) > 0 {
		builder.WriteString("    environment:\n")
		keys := make([]string, 0, len(service.Env))
		for key := range service.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			builder.WriteString(fmt.Sprintf("      %s: \"%s\"\n", key, service.Env[key]))
		}
	}

	if len(service.Volumes) > 0 {
		builder.WriteString("    volumes:\n")
		for _, volume := range service.Volumes {
			builder.WriteString(fmt.Sprintf("      - %s\n", volume))
		}
	}

	if len(service.Ports) > 0 {
		builder.WriteString("    ports:\n")
		for _, port := range service.Ports {
			mapping := fmt.Sprintf("%d:%d", port.Host, port.Container)
			if strings.TrimSpace(port.Protocol) != "" {
				mapping = fmt.Sprintf("%s/%s", mapping, port.Protocol)
			}
			builder.WriteString(fmt.Sprintf("      - \"%s\"\n", mapping))
		}
	}
}
