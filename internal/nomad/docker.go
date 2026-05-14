package nomad

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

type ContainerConfig struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Image    string                 `json:"image"`
	Status   string                 `json:"status"`
	Ports    []string               `json:"ports"`
	Env      []string               `json:"env"`
	Volumes  []string               `json:"volumes"`
	Labels   map[string]string      `json:"labels"`
	Networks map[string]interface{} `json:"networks"`
}

type DockerState struct {
	Containers  []ContainerConfig      `json:"containers"`
	Images      []string               `json:"images"`
	Networks    map[string]interface{} `json:"networks"`
	Volumes     []string               `json:"volumes"`
	VolumeData  map[string][]byte      `json:"volume_data"`
	ComposeYaml string                 `json:"compose_yaml"`
}

func ExtractDockerState(client sshutil.SSHRunner) (*DockerState, error) {
	slog.Info("extracting docker state")

	state := &DockerState{
		Networks:   make(map[string]interface{}),
		VolumeData: make(map[string][]byte),
	}

	containers, err := extractContainers(client)
	if err != nil {
		slog.Warn("failed to extract containers", "error", err)
	} else {
		state.Containers = containers
	}

	images, err := extractImages(client)
	if err != nil {
		slog.Warn("failed to extract image list", "error", err)
	} else {
		state.Images = images
	}

	volumes, err := extractVolumes(client)
	if err != nil {
		slog.Warn("failed to extract volumes", "error", err)
	} else {
		state.Volumes = volumes
	}

	if volumeData, err := extractVolumeData(client); err == nil {
		state.VolumeData = volumeData
	} else {
		slog.Warn("failed to extract volume data", "error", err)
	}

	composeYaml, err := extractDockerCompose(client)
	if err != nil {
		slog.Debug("docker-compose.yaml not found or extraction failed")
	} else {
		state.ComposeYaml = composeYaml
	}

	slog.Info("docker state extracted",
		"containers", len(state.Containers),
		"images", len(state.Images),
		"volumes", len(state.Volumes),
		"volume_data_entries", len(state.VolumeData),
	)

	return state, nil
}

func extractContainers(client sshutil.SSHRunner) ([]ContainerConfig, error) {
	out, err := client.Run("docker ps -a --format '{{json .}}'")
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	var containers []ContainerConfig
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}

		var c ContainerConfig
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			slog.Debug("failed to parse container", "line", line)
			continue
		}

		fullConfig, err := extractFullContainerConfig(client, c.ID)
		if err == nil {
			c = fullConfig
		}

		containers = append(containers, c)
	}

	return containers, nil
}

func extractFullContainerConfig(client sshutil.SSHRunner, containerID string) (ContainerConfig, error) {
	out, err := client.Run(fmt.Sprintf("docker inspect %s", containerID))
	if err != nil {
		return ContainerConfig{}, err
	}

	var inspectResult []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &inspectResult); err != nil {
		return ContainerConfig{}, err
	}

	if len(inspectResult) == 0 {
		return ContainerConfig{}, fmt.Errorf("no inspect data")
	}

	config := ContainerConfig{
		ID:       containerID,
		Labels:   make(map[string]string),
		Networks: make(map[string]interface{}),
		Env:      []string{},
		Volumes:  []string{},
		Ports:    []string{},
	}

	data := inspectResult[0]
	if name, ok := data["Name"].(string); ok {
		config.Name = strings.TrimPrefix(name, "/")
	}
	if image, ok := data["Image"].(string); ok {
		config.Image = image
	}
	if state, ok := data["State"].(map[string]interface{}); ok {
		if status, ok := state["Status"].(string); ok {
			config.Status = status
		}
	}

	if containerConfig, ok := data["Config"].(map[string]interface{}); ok {
		if env, ok := containerConfig["Env"].([]interface{}); ok {
			for _, e := range env {
				if s, ok := e.(string); ok {
					config.Env = append(config.Env, s)
				}
			}
		}

		if labels, ok := containerConfig["Labels"].(map[string]interface{}); ok {
			for k, v := range labels {
				if s, ok := v.(string); ok {
					config.Labels[k] = s
				}
			}
		}
	}

	if hostConfig, ok := data["HostConfig"].(map[string]interface{}); ok {
		if binds, ok := hostConfig["Binds"].([]interface{}); ok {
			for _, b := range binds {
				if s, ok := b.(string); ok {
					config.Volumes = append(config.Volumes, s)
				}
			}
		}

		if portBindings, ok := hostConfig["PortBindings"].(map[string]interface{}); ok {
			for port := range portBindings {
				config.Ports = append(config.Ports, port)
			}
		}
	}

	if networkSettings, ok := data["NetworkSettings"].(map[string]interface{}); ok {
		if networks, ok := networkSettings["Networks"].(map[string]interface{}); ok {
			config.Networks = networks
		}
	}

	return config, nil
}

func extractImages(client sshutil.SSHRunner) ([]string, error) {
	out, err := client.Run("docker images --format '{{.Repository}}:{{.Tag}}'")
	if err != nil {
		return nil, fmt.Errorf("docker images failed: %w", err)
	}

	var images []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" && line != "<none>:<none>" {
			images = append(images, line)
		}
	}

	return images, nil
}

func extractVolumes(client sshutil.SSHRunner) ([]string, error) {
	out, err := client.Run("docker volume ls --format '{{.Name}}'")
	if err != nil {
		return nil, fmt.Errorf("docker volume ls failed: %w", err)
	}

	var volumes []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			volumes = append(volumes, line)
		}
	}

	return volumes, nil
}

func extractVolumeData(client sshutil.SSHRunner) (map[string][]byte, error) {
	volumeData := make(map[string][]byte)

	out, err := client.Run("docker volume ls --format '{{.Name}}'")
	if err != nil {
		return volumeData, fmt.Errorf("docker volume ls failed: %w", err)
	}

	for _, volumeName := range strings.Split(strings.TrimSpace(out), "\n") {
		volumeName = strings.TrimSpace(volumeName)
		if volumeName == "" {
			continue
		}

		tarCmd := fmt.Sprintf("tar czf - -C /var/lib/docker/volumes/%s . 2>/dev/null", volumeName)

		data, err := client.Run(tarCmd)
		if err != nil {
			slog.Warn("failed to tar volume", "volume", volumeName, "error", err)
			continue
		}

		volumeData[volumeName] = []byte(data)
		slog.Debug("captured volume data", "volume", volumeName, "size", len(data))
	}

	return volumeData, nil
}

func extractDockerCompose(client sshutil.SSHRunner) (string, error) {
	possiblePaths := []string{
		"/opt/3x-ui/docker-compose.yaml",
		"/opt/3x-ui/docker-compose.yml",
		"/opt/docker-compose.yaml",
		"/root/docker-compose.yaml",
	}

	for _, path := range possiblePaths {
		out, err := client.Run(fmt.Sprintf("cat %s 2>/dev/null", path))
		if err == nil && len(out) > 0 {
			slog.Info("found docker-compose", "path", path)
			return out, nil
		}
	}

	return "", fmt.Errorf("docker-compose.yaml not found")
}

func RestoreDockerState(client sshutil.SSHRunner, state *DockerState) error {
	slog.Info("restoring docker state", "containers", len(state.Containers))

	if err := restoreVolumeData(client, state.VolumeData); err != nil {
		slog.Warn("failed to restore volume data", "error", err)
	}

	if state.ComposeYaml != "" {
		if err := restoreComposeYaml(client, state.ComposeYaml); err != nil {
			slog.Warn("failed to restore docker-compose", "error", err)
		}
	}

	for _, container := range state.Containers {
		if err := restoreContainer(client, container); err != nil {
			slog.Warn("failed to restore container", "name", container.Name, "error", err)
			continue
		}
		slog.Info("container restored", "name", container.Name)
	}

	return nil
}

func restoreVolumeData(client sshutil.SSHRunner, volumeData map[string][]byte) error {
	if len(volumeData) == 0 {
		slog.Info("no volume data to restore")
		return nil
	}

	slog.Info("restoring docker volumes", "count", len(volumeData))

	for volumeName, data := range volumeData {
		volumePath := fmt.Sprintf("/var/lib/docker/volumes/%s/_data", volumeName)
		client.Run(fmt.Sprintf("mkdir -p %s", volumePath))

		writeCmd := fmt.Sprintf("cat > /tmp/%s.tar.gz << 'EOF'\n%s\nEOF", volumeName, string(data))
		if _, err := client.Run(writeCmd); err != nil {
			slog.Warn("failed to write volume data", "volume", volumeName, "error", err)
			continue
		}

		extractCmd := fmt.Sprintf("tar xzf /tmp/%s.tar.gz -C %s && rm /tmp/%s.tar.gz", volumeName, volumePath, volumeName)
		if _, err := client.Run(extractCmd); err != nil {
			slog.Warn("failed to extract volume data", "volume", volumeName, "error", err)
			continue
		}

		slog.Info("volume restored", "volume", volumeName)
	}

	return nil
}

func restoreComposeYaml(client sshutil.SSHRunner, yamlContent string) error {
	composeDir := "/opt/3x-ui"
	client.Run(fmt.Sprintf("mkdir -p %s", composeDir))

	writeCmd := fmt.Sprintf("cat > %s/docker-compose.yaml << 'EOF'\n%s\nEOF", composeDir, yamlContent)
	if _, err := client.Run(writeCmd); err != nil {
		return fmt.Errorf("failed to write docker-compose.yaml: %w", err)
	}

	upCmd := fmt.Sprintf("cd %s && docker compose up -d", composeDir)
	_, err := client.Run(upCmd)
	if err != nil {
		return fmt.Errorf("docker compose up failed: %w", err)
	}

	return nil
}

func restoreContainer(client sshutil.SSHRunner, container ContainerConfig) error {
	if container.Image == "" {
		return fmt.Errorf("container %s has no image", container.Name)
	}

	runCmd := fmt.Sprintf("docker run -d --name %s --restart unless-stopped", container.Name)

	for _, env := range container.Env {
		runCmd += fmt.Sprintf(" -e '%s'", env)
	}

	for _, port := range container.Ports {
		runCmd += fmt.Sprintf(" -p %s", port)
	}

	for _, volume := range container.Volumes {
		runCmd += fmt.Sprintf(" -v %s", volume)
	}

	for k, v := range container.Labels {
		runCmd += fmt.Sprintf(" -l %s=%s", k, v)
	}

	runCmd += fmt.Sprintf(" %s", container.Image)

	out, err := client.Run(runCmd)
	if err != nil {
		return fmt.Errorf("container start failed: %s - %w", out, err)
	}

	return nil
}

func validateContainerdRuntime(client sshutil.SSHRunner) bool {
	_, err := client.Run("which containerd")
	return err == nil
}

func ValidateDockerState(client sshutil.SSHRunner) error {
	slog.Info("validating docker installation")

	_, err := client.Run("docker --version")
	if err != nil {
		return fmt.Errorf("docker not installed: %w", err)
	}

	_, err = client.Run("docker ps")
	if err != nil {
		return fmt.Errorf("docker daemon not responding: %w", err)
	}

	return nil
}
