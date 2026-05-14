package extractor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

// ExtractDatabase retrieves SQLite database with privilege escalation
func ExtractDatabase(client sshutil.SSHRunner, dbPath string) ([]byte, error) {
	slog.Info("extracting database", "path", dbPath)

	out, err := client.Run(fmt.Sprintf("cat %s 2>/dev/null", dbPath))
	if err == nil && len(out) > 0 {
		slog.Debug("database read successfully", "path", dbPath, "size_kb", len(out)/1024)
		return []byte(out), nil
	}

	out, err = client.Run(fmt.Sprintf("sudo cat %s 2>/dev/null", dbPath))
	if err == nil && len(out) > 0 {
		slog.Debug("database read with sudo", "path", dbPath, "size_kb", len(out)/1024)
		return []byte(out), nil
	}

	out, err = client.Run(fmt.Sprintf("sudo -u root cat %s 2>/dev/null || sudo cat %s 2>/dev/null", dbPath, dbPath))
	if err == nil && len(out) > 0 {
		slog.Debug("database read with elevated privileges", "path", dbPath, "size_kb", len(out)/1024)
		return []byte(out), nil
	}

	return nil, fmt.Errorf("unable to read database: %s", dbPath)
}

// ExtractAllDatabases scans standard paths for x-ui databases
func ExtractAllDatabases(client sshutil.SSHRunner) (map[string][]byte, error) {
	slog.Info("scanning for all SQLite databases")

	databases := make(map[string][]byte)

	dbPaths := []string{
		"/opt/3x-ui/db/x-ui.db",
		"/opt/x-ui/db/x-ui.db",
		"/app/db/x-ui.db",
		"/var/lib/xui/x-ui.db",
		"/root/.config/x-ui/db/x-ui.db",
		"/home/x-ui/.config/x-ui/db/x-ui.db",
		"/opt/xray/db/x-ui.db",
		"/etc/x-ui/db/x-ui.db",
	}

	for _, path := range dbPaths {
		data, err := ExtractDatabase(client, path)
		if err != nil {
			slog.Debug("database not accessible", "path", path)
			continue
		}

		if len(data) > 0 {
			slog.Info("database found and extracted", "path", path, "size_kb", len(data)/1024)
			databases[path] = data
		}
	}

	if len(databases) == 0 {
		slog.Warn("no databases found in standard locations")
	}

	return databases, nil
}

// VerifyDatabaseIntegrity validates SQLite header and minimum size
func VerifyDatabaseIntegrity(data []byte) error {
	slog.Debug("verifying database integrity")

	const sqliteHeader = "SQLite format 3"
	if len(data) < len(sqliteHeader) {
		return fmt.Errorf("data too small to be a valid sqlite database: %d bytes", len(data))
	}

	if string(data[:len(sqliteHeader)]) != sqliteHeader {
		return fmt.Errorf("invalid sqlite header: expected 'SQLite format 3', got %q", string(data[:len(sqliteHeader)]))
	}

	if len(data) < 512 {
		return fmt.Errorf("database file too small: %d bytes (minimum 512)", len(data))
	}

	slog.Debug("database integrity verified", "size_bytes", len(data))
	return nil
}

// DatabaseMetadata collects file stats: size, time, permissions, owner, sha256
func DatabaseMetadata(client sshutil.SSHRunner, dbPath string) (map[string]string, error) {
	slog.Debug("collecting database metadata", "path", dbPath)

	metadata := make(map[string]string)

	out, err := client.Run(fmt.Sprintf("stat -c %%s %s 2>/dev/null || stat -f %%z %s 2>/dev/null", dbPath, dbPath))
	if err == nil {
		metadata["size_bytes"] = strings.TrimSpace(out)
	}

	out, err = client.Run(fmt.Sprintf("stat -c %%y %s 2>/dev/null | cut -d' ' -f1-2", dbPath))
	if err == nil {
		metadata["modified"] = strings.TrimSpace(out)
	}

	out, err = client.Run(fmt.Sprintf("stat -c %%a %s 2>/dev/null", dbPath))
	if err == nil {
		metadata["permissions"] = strings.TrimSpace(out)
	}

	out, err = client.Run(fmt.Sprintf("stat -c %%U:%%G %s 2>/dev/null", dbPath))
	if err == nil {
		metadata["owner"] = strings.TrimSpace(out)
	}

	out, err = client.Run(fmt.Sprintf("sha256sum %s 2>/dev/null | cut -d' ' -f1", dbPath))
	if err == nil {
		metadata["sha256"] = strings.TrimSpace(out)
	}

	slog.Debug("database metadata collected", "path", dbPath, "fields", len(metadata))
	return metadata, nil
}

// BackupDatabasePath detects primary database or returns default
func BackupDatabasePath(client sshutil.SSHRunner) (string, error) {
	slog.Debug("detecting primary database path")

	out, err := client.Run("find /opt /app /var/lib -name '*x-ui*.db' -type f 2>/dev/null | head -1")
	if err == nil && strings.TrimSpace(out) != "" {
		path := strings.TrimSpace(out)
		slog.Info("detected database path", "path", path)
		return path, nil
	}

	defaultPath := "/opt/3x-ui/db/x-ui.db"
	slog.Info("using default database path", "path", defaultPath)
	return defaultPath, nil
}

// CompareDatabase returns size/hash/growth diff
func CompareDatabase(oldData, newData []byte) map[string]interface{} {
	slog.Debug("comparing databases")

	result := make(map[string]interface{})

	result["old_size_bytes"] = len(oldData)
	result["new_size_bytes"] = len(newData)
	result["size_change_bytes"] = len(newData) - len(oldData)

	oldHash := sha256.Sum256(oldData)
	newHash := sha256.Sum256(newData)
	result["old_hash"] = hex.EncodeToString(oldHash[:])
	result["new_hash"] = hex.EncodeToString(newHash[:])
	result["identical"] = oldHash == newHash

	if len(newData) > len(oldData) {
		result["growth_percent"] = float64(len(newData)-len(oldData)) / float64(len(oldData)) * 100
	}

	slog.Debug("database comparison completed", "identical", oldHash == newHash)
	return result
}

// ValidateDatabaseBackup checks database backup completeness
func ValidateDatabaseBackup(data []byte, srcPath string) error {
	slog.Info("validating database backup", "source_path", srcPath)

	if err := VerifyDatabaseIntegrity(data); err != nil {
		return fmt.Errorf("database integrity check failed: %w", err)
	}

	minSize := 65536
	if len(data) < minSize {
		slog.Warn("database backup might be incomplete", "size_bytes", len(data), "min_expected", minSize)
	}

	slog.Info("database backup validation completed", "size_bytes", len(data))
	return nil
}
