package extractor

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

// ExtractCertificates retrieves all Let's Encrypt certificates from the server
func ExtractCertificates(client sshutil.SSHRunner) (map[string][]byte, error) {
	slog.Info("extracting let's encrypt certificates")

	certs := make(map[string][]byte)

	out, err := client.Run("ls -la /etc/letsencrypt/live/ 2>/dev/null | tail -n +4 | awk '{print $NF}'")
	if err != nil || strings.TrimSpace(out) == "" {
		slog.Debug("no letsencrypt certificates found")
		return certs, nil
	}

	domains := strings.Fields(out)
	slog.Debug("found domains", "count", len(domains))

	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" || domain == "." || domain == ".." {
			continue
		}

		slog.Debug("extracting certificate", "domain", domain)

		certPath := fmt.Sprintf("/etc/letsencrypt/live/%s/cert.pem", domain)
		certData, err := readRemoteFile(client, certPath)
		if err != nil {
			slog.Warn("failed to read cert", "domain", domain, "error", err)
			continue
		}
		certs[fmt.Sprintf("%s/cert.pem", domain)] = certData

		keyPath := fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", domain)
		keyData, err := readRemoteFile(client, keyPath)
		if err != nil {
			slog.Warn("failed to read privkey", "domain", domain, "error", err)
			continue
		}
		certs[fmt.Sprintf("%s/privkey.pem", domain)] = keyData

		chainPath := fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", domain)
		chainData, err := readRemoteFile(client, chainPath)
		if err != nil {
			slog.Warn("failed to read fullchain", "domain", domain, "error", err)
			continue
		}
		certs[fmt.Sprintf("%s/fullchain.pem", domain)] = chainData

		slog.Info("certificate extracted successfully", "domain", domain)
	}

	slog.Info("certificate extraction completed", "total_files", len(certs))
	return certs, nil
}

// ExtractXrayConfig retrieves Xray configuration from the server
func ExtractXrayConfig(client sshutil.SSHRunner) ([]byte, error) {
	slog.Debug("extracting xray configuration")

	commonPaths := []string{
		"/etc/xray/config.json",
		"/opt/xray/config.json",
		"/app/config.json",
		"/usr/local/etc/xray/config.json",
	}

	for _, path := range commonPaths {
		data, err := readRemoteFile(client, path)
		if err != nil {
			slog.Debug("xray config not found", "path", path)
			continue
		}

		if len(data) > 0 {
			slog.Info("xray config extracted", "path", path, "size", len(data))
			return data, nil
		}
	}

	slog.Debug("no xray config found in standard locations")
	return nil, fmt.Errorf("xray config not found")
}

// ExtractXrayState retrieves full Xray state (config and statistics)
func ExtractXrayState(client sshutil.SSHRunner) (map[string][]byte, error) {
	slog.Info("extracting xray full state")

	state := make(map[string][]byte)

	config, err := ExtractXrayConfig(client)
	if err == nil && len(config) > 0 {
		state["config.json"] = config
	}

	out, err := client.Run("curl -s http://127.0.0.1:10085/query 2>/dev/null | head -c 10000")
	if err == nil && len(out) > 0 {
		state["xray_stats.json"] = []byte(out)
		slog.Debug("xray stats extracted")
	}

	slog.Info("xray state extraction completed", "items", len(state))
	return state, nil
}

// readRemoteFile reads remote file content, with sudo fallback for protected files
func readRemoteFile(client sshutil.SSHRunner, filePath string) ([]byte, error) {
	out, err := client.Run(fmt.Sprintf("cat %s 2>/dev/null", filePath))
	if err == nil && len(out) > 0 {
		return []byte(out), nil
	}

	out, err = client.Run(fmt.Sprintf("sudo cat %s 2>/dev/null", filePath))
	if err == nil && len(out) > 0 {
		return []byte(out), nil
	}

	return nil, fmt.Errorf("unable to read file: %s", filePath)
}

// BackupCertificatePaths returns list of certificate paths on the server
func BackupCertificatePaths(client sshutil.SSHRunner) ([]string, error) {
	slog.Debug("retrieving certificate paths")

	var paths []string

	out, err := client.Run("find /etc/letsencrypt/live/ -type f -name '*.pem' 2>/dev/null")
	if err != nil {
		slog.Debug("find command failed", "error", err)
		return paths, nil
	}

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" {
			paths = append(paths, line)
		}
	}

	slog.Debug("certificate paths retrieved", "count", len(paths))
	return paths, nil
}
