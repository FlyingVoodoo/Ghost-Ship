package extractor

import (
	"testing"

	"github.com/matvejefimovyh/ghost-ship/internal/mocks"
)

func TestBackupDatabasePath_Finds(t *testing.T) {
	mock := mocks.NewMockSSHRunner(map[string]string{
		"find /opt /app /var/lib -name": "/opt/3x-ui/db/x-ui.db\n",
	})

	path, err := BackupDatabasePath(mock)
	if err != nil {
		t.Fatalf("BackupDatabasePath error: %v", err)
	}
	if path != "/opt/3x-ui/db/x-ui.db" {
		t.Fatalf("unexpected path: %q", path)
	}
}

func TestExtractDatabase_Sudo(t *testing.T) {
	dbContent := "SQLITE3DATA"
	mock := mocks.NewMockSSHRunner(map[string]string{
		"/opt/3x-ui/db/x-ui.db": dbContent,
	})

	data, err := ExtractDatabase(mock, "/opt/3x-ui/db/x-ui.db")
	if err != nil {
		t.Fatalf("ExtractDatabase error: %v", err)
	}
	if string(data) != dbContent {
		t.Fatalf("unexpected db content")
	}
}

func TestExtractXrayConfig_Found(t *testing.T) {
	cfg := "{\"inbounds\":[] }"
	mock := mocks.NewMockSSHRunner(map[string]string{
		"/etc/xray/config.json": cfg,
	})

	data, err := ExtractXrayConfig(mock)
	if err != nil {
		t.Fatalf("ExtractXrayConfig error: %v", err)
	}
	if string(data) != cfg {
		t.Fatalf("unexpected xray config")
	}
}

func TestExtractAllDatabases(t *testing.T) {
	mock := mocks.NewMockSSHRunner(map[string]string{
		"/opt/3x-ui/db/x-ui.db": "DBDATA",
	})

	m, err := ExtractAllDatabases(mock)
	if err != nil {
		t.Fatalf("ExtractAllDatabases error: %v", err)
	}
	if len(m) == 0 {
		t.Fatalf("expected databases to be found")
	}
}
