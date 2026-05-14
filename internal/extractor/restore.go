package extractor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

type remoteFileInfo struct {
	sha256 string
	size   int
}

func restoreBytesIfChanged(client sshutil.SSHRunner, remotePath string, data []byte, useSudo bool) error {
	if len(data) == 0 {
		slog.Info("skipping empty restore payload", "path", remotePath)
		return nil
	}

	localHash := sha256.Sum256(data)
	localHashHex := hex.EncodeToString(localHash[:])

	current, err := inspectRemoteFile(client, remotePath, useSudo)
	if err == nil && current.sha256 == localHashHex && current.size == len(data) {
		slog.Info("remote file already up to date", "path", remotePath)
		return nil
	}

	if err := ensureRemoteParentDir(client, remotePath, useSudo); err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	teeCmd := "tee"
	if useSudo {
		teeCmd = "sudo tee"
	}
	writeCmd := fmt.Sprintf("echo '%s' | base64 -d | %s %s > /dev/null", encoded, teeCmd, remotePath)
	if _, err := client.Run(writeCmd); err != nil {
		return fmt.Errorf("failed to write %s: %w", remotePath, err)
	}

	verified, err := inspectRemoteFile(client, remotePath, useSudo)
	if err != nil {
		return fmt.Errorf("failed to verify %s after restore: %w", remotePath, err)
	}
	if verified.sha256 != localHashHex || verified.size != len(data) {
		return fmt.Errorf("checksum mismatch for %s after restore: want %s/%d got %s/%d", remotePath, localHashHex, len(data), verified.sha256, verified.size)
	}

	slog.Info("file restored and verified", "path", remotePath, "size", len(data))
	return nil
}

func ensureRemoteParentDir(client sshutil.SSHRunner, remotePath string, useSudo bool) error {
	parentDir := filepath.Dir(remotePath)
	cmd := fmt.Sprintf("mkdir -p %s", parentDir)
	if useSudo {
		cmd = fmt.Sprintf("sudo %s", cmd)
	}
	if _, err := client.Run(cmd); err != nil {
		return fmt.Errorf("failed to create parent directory for %s: %w", remotePath, err)
	}
	return nil
}

func inspectRemoteFile(client sshutil.SSHRunner, remotePath string, useSudo bool) (remoteFileInfo, error) {
	prefix := ""
	if useSudo {
		prefix = "sudo "
	}

	shaCmd := fmt.Sprintf("%ssha256sum %s 2>/dev/null", prefix, remotePath)
	shaOut, err := client.Run(shaCmd)
	if err != nil || strings.TrimSpace(shaOut) == "" {
		return remoteFileInfo{}, fmt.Errorf("remote file not accessible: %s", remotePath)
	}
	shaFields := strings.Fields(strings.TrimSpace(shaOut))
	if len(shaFields) == 0 {
		return remoteFileInfo{}, fmt.Errorf("unexpected sha256sum output for %s", remotePath)
	}

	statCmd := fmt.Sprintf("%sstat -c %%s %s 2>/dev/null || %sstat -f %%z %s 2>/dev/null", prefix, remotePath, prefix, remotePath)
	sizeOut, err := client.Run(statCmd)
	if err != nil || strings.TrimSpace(sizeOut) == "" {
		return remoteFileInfo{}, fmt.Errorf("remote file size not accessible: %s", remotePath)
	}
	sizeVal, err := strconv.Atoi(strings.TrimSpace(sizeOut))
	if err != nil {
		return remoteFileInfo{}, fmt.Errorf("invalid remote file size for %s: %w", remotePath, err)
	}

	return remoteFileInfo{sha256: shaFields[0], size: sizeVal}, nil
}
