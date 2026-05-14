package extractor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/matvejefimovyh/ghost-ship/internal/mocks"
)

func TestRestoreBytesIfChanged_SkipsWhenChecksumMatches(t *testing.T) {
	data := []byte("hello world")
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])
	remotePath := "/opt/3x-ui/db/x-ui.db"

	mock := mocks.NewMockSSHRunner(nil)
	mock.Scripts = []mocks.MockScript{
		{Contains: fmt.Sprintf("sudo sha256sum %s", remotePath), Outcomes: []mocks.MockOutcome{{Response: fmt.Sprintf("%s  %s", hashHex, remotePath)}}},
		{Contains: fmt.Sprintf("sudo stat -c %%s %s", remotePath), Outcomes: []mocks.MockOutcome{{Response: fmt.Sprintf("%d", len(data))}}},
	}

	if err := restoreBytesIfChanged(mock, remotePath, data, true); err != nil {
		t.Fatalf("restoreBytesIfChanged returned error: %v", err)
	}

	for _, cmd := range mock.Commands {
		if strings.Contains(cmd, "tee "+remotePath) {
			t.Fatalf("expected no write when checksum matches, but saw command %q", cmd)
		}
	}
}

func TestRestoreBytesIfChanged_WritesAndVerifies(t *testing.T) {
	data := []byte("new db content")
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])
	remotePath := "/etc/x-ui/xray.json"
	encoded := "bmV3IGRiIGNvbnRlbnQ="

	mock := mocks.NewMockSSHRunner(nil)
	mock.Scripts = []mocks.MockScript{
		{Contains: fmt.Sprintf("sudo sha256sum %s", remotePath), Outcomes: []mocks.MockOutcome{{Err: fmt.Errorf("not found")}, {Response: fmt.Sprintf("%s  %s", hashHex, remotePath)}}},
		{Contains: "sudo mkdir -p /etc/x-ui", Outcomes: []mocks.MockOutcome{{Response: ""}}},
		{Contains: fmt.Sprintf("sudo tee %s", remotePath), Outcomes: []mocks.MockOutcome{{Response: "written"}}},
		{Contains: fmt.Sprintf("sudo stat -c %%s %s", remotePath), Outcomes: []mocks.MockOutcome{{Response: fmt.Sprintf("%d", len(data))}, {Response: fmt.Sprintf("%d", len(data))}}},
		{Contains: encoded, Outcomes: []mocks.MockOutcome{{Response: encoded}}},
	}

	if err := restoreBytesIfChanged(mock, remotePath, data, true); err != nil {
		t.Fatalf("restoreBytesIfChanged returned error: %v", err)
	}

	seenWrite := false
	for _, cmd := range mock.Commands {
		if strings.Contains(cmd, "tee "+remotePath) {
			seenWrite = true
		}
	}
	if !seenWrite {
		t.Fatalf("expected a write command to be executed")
	}
}

func TestRestoreSystemState_RestoresCertificates(t *testing.T) {
	data := []byte("cert-data")
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])
	remotePath := "/etc/letsencrypt/live/example.com/cert.pem"

	mock := mocks.NewMockSSHRunner(nil)
	mock.Scripts = []mocks.MockScript{
		{Contains: fmt.Sprintf("sudo sha256sum %s", remotePath), Outcomes: []mocks.MockOutcome{{Err: fmt.Errorf("not found")}, {Response: fmt.Sprintf("%s  %s", hashHex, remotePath)}}},
		{Contains: fmt.Sprintf("sudo mkdir -p /etc/letsencrypt/live/example.com"), Outcomes: []mocks.MockOutcome{{Response: ""}}},
		{Contains: fmt.Sprintf("sudo tee %s", remotePath), Outcomes: []mocks.MockOutcome{{Response: "written"}}},
		{Contains: fmt.Sprintf("sudo stat -c %%s %s", remotePath), Outcomes: []mocks.MockOutcome{{Response: fmt.Sprintf("%d", len(data))}}},
	}

	state := &SystemState{
		Certificates: map[string][]byte{"example.com/cert.pem": data},
	}

	if err := RestoreSystemState(mock, state); err != nil {
		t.Fatalf("RestoreSystemState returned error: %v", err)
	}

	seenWrite := false
	for _, cmd := range mock.Commands {
		if strings.Contains(cmd, remotePath) && strings.Contains(cmd, "tee") {
			seenWrite = true
		}
	}
	if !seenWrite {
		t.Fatalf("expected certificate write command to be executed")
	}
}
