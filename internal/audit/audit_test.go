package audit

import (
	"testing"

	"github.com/matvejefimovyh/ghost-ship/internal/mocks"
)

func TestRunSecurityAudit_AllPass(t *testing.T) {
	mock := mocks.NewMockSSHRunner(map[string]string{
		"hostname":                               "test-host\n",
		"passwordauthentication no":              "PasswordAuthentication no\n",
		"ufw status":                             "Status: active\n",
		"fail2ban":                               "active\n",
		"getenforce":                             "Enforcing\n",
		"audit.*sudo":                            "-a always,exit -F arch=b64 -S execve -k sudo",
		"which docker":                           "/usr/bin/docker\n",
		"docker info":                            "Security Options: seccomp\n",
		"docker ps":                              "CONTAINER ID\n",
		"ls -l /var/run/docker.sock":             "srw-rw----",
		"nomad job list":                         "[]",
		"nomad job inspect":                      "{}",
		"grep -i 'tls.*true'":                    "tls = true",
		"grep -i 'acl.*enabled'":                 "acl { enabled = true }",
		"grep -i 'audit' /etc/nomad.d/nomad.hcl": "audit = true",
	})

	report, err := RunSecurityAudit(mock, nil)
	if err != nil {
		t.Fatalf("RunSecurityAudit returned error: %v", err)
	}

	if report.Hostname != "test-host" {
		t.Fatalf("unexpected hostname: %q", report.Hostname)
	}

	if report.PassedCount == 0 {
		t.Fatalf("expected some passed checks, got 0")
	}
}
