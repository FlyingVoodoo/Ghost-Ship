package audit

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

type SecurityAlert struct {
	Level     string
	Component string
	Issue     string
	Details   string
	Timestamp int64
}

type AuditReport struct {
	Hostname      string
	Timestamp     int64
	SystemChecks  []SecurityAlert
	DockerChecks  []SecurityAlert
	NomadChecks   []SecurityAlert
	CriticalCount int
	WarningCount  int
	PassedCount   int
}

type TelegramConfig struct {
	BotToken string
	ChatID   string
}

func RunSecurityAudit(client *sshutil.SSHClient, telegramCfg *TelegramConfig) (*AuditReport, error) {
	slog.Info("starting security audit")

	hostname, _ := client.Run("hostname")
	hostname = strings.TrimSpace(hostname)

	report := &AuditReport{
		Hostname:     hostname,
		Timestamp:    time.Now().Unix(),
		SystemChecks: []SecurityAlert{},
		DockerChecks: []SecurityAlert{},
		NomadChecks:  []SecurityAlert{},
	}

	auditSystemSecurity(client, report)
	auditDockerSecurity(client, report)
	auditNomadSecurity(client, report)

	slog.Info("audit completed",
		"critical", report.CriticalCount,
		"warnings", report.WarningCount,
		"passed", report.PassedCount,
	)

	if telegramCfg != nil && telegramCfg.BotToken != "" {
		if err := sendAuditReport(telegramCfg, report); err != nil {
			slog.Warn("failed to send telegram report", "error", err)
		}
	}

	return report, nil
}

func auditSystemSecurity(client *sshutil.SSHClient, report *AuditReport) {
	slog.Debug("auditing system security")

	checks := []struct {
		name  string
		cmd   string
		pass  func(string) bool
		issue string
	}{
		{
			name:  "SSH key-based auth",
			cmd:   "grep -i 'passwordauthentication no' /etc/ssh/sshd_config",
			pass:  func(s string) bool { return len(s) > 0 },
			issue: "SSH password authentication is enabled",
		},
		{
			name:  "Firewall active",
			cmd:   "sudo ufw status | grep 'Status: active'",
			pass:  func(s string) bool { return len(s) > 0 },
			issue: "UFW firewall is not active",
		},
		{
			name:  "Fail2Ban running",
			cmd:   "sudo systemctl is-active fail2ban",
			pass:  func(s string) bool { return strings.Contains(s, "active") },
			issue: "Fail2Ban service is not running",
		},
		{
			name:  "SELinux/AppArmor",
			cmd:   "getenforce 2>/dev/null || aa-status 2>/dev/null | head -1",
			pass:  func(s string) bool { return len(strings.TrimSpace(s)) > 0 },
			issue: "No MAC (SELinux/AppArmor) detected",
		},
		{
			name:  "Sudo audit logging",
			cmd:   "grep -i 'audit.*sudo' /etc/audit/rules.d/* 2>/dev/null | head -1",
			pass:  func(s string) bool { return len(s) > 0 },
			issue: "Sudo commands are not being audited",
		},
	}

	for _, check := range checks {
		out, _ := client.Run(check.cmd)
		if check.pass(out) {
			report.PassedCount++
			slog.Debug("check passed", "name", check.name)
		} else {
			alert := SecurityAlert{
				Level:     "WARNING",
				Component: "SYSTEM",
				Issue:     check.name,
				Details:   check.issue,
			}
			report.WarningCount++
			report.SystemChecks = append(report.SystemChecks, alert)
			slog.Warn("check failed", "name", check.name)
		}
	}
}

func auditDockerSecurity(client *sshutil.SSHClient, report *AuditReport) {
	slog.Debug("auditing docker security")

	if _, err := client.Run("which docker"); err != nil {
		alert := SecurityAlert{
			Level:     "INFO",
			Component: "DOCKER",
			Issue:     "Docker not installed",
			Details:   "Docker is not installed on this system",
		}
		report.DockerChecks = append(report.DockerChecks, alert)
		return
	}

	checks := []struct {
		name  string
		cmd   string
		pass  func(string) bool
		issue string
		level string
	}{
		{
			name:  "Docker daemon security",
			cmd:   "docker info | grep 'Security Options'",
			pass:  func(s string) bool { return len(s) > 10 },
			issue: "Docker daemon has no security options enabled",
			level: "WARNING",
		},
		{
			name:  "Container resource limits",
			cmd:   "docker ps --format '{{.Names}}' | xargs -I {} docker inspect {} | grep -i 'memory.*0' | wc -l",
			pass:  func(s string) bool { return strings.TrimSpace(s) == "0" },
			issue: "Some containers have no memory limits",
			level: "WARNING",
		},
		{
			name:  "Privileged containers",
			cmd:   "docker ps --format '{{json .}}' | grep -i privileged | wc -l",
			pass:  func(s string) bool { return strings.TrimSpace(s) == "0" },
			issue: "Privileged containers detected",
			level: "CRITICAL",
		},
		{
			name:  "Docker socket permissions",
			cmd:   "ls -l /var/run/docker.sock | awk '{print $1}'",
			pass:  func(s string) bool { return strings.Contains(s, "srw") },
			issue: "Docker socket has incorrect permissions",
			level: "CRITICAL",
		},
	}

	for _, check := range checks {
		out, _ := client.Run(check.cmd)
		if check.pass(out) {
			report.PassedCount++
		} else {
			alert := SecurityAlert{
				Level:     check.level,
				Component: "DOCKER",
				Issue:     check.name,
				Details:   check.issue,
			}
			if check.level == "CRITICAL" {
				report.CriticalCount++
			} else {
				report.WarningCount++
			}
			report.DockerChecks = append(report.DockerChecks, alert)
		}
	}
}

func auditNomadSecurity(client *sshutil.SSHClient, report *AuditReport) {
	slog.Debug("auditing nomad security")

	if _, err := client.Run("which nomad"); err != nil {
		alert := SecurityAlert{
			Level:     "INFO",
			Component: "NOMAD",
			Issue:     "Nomad not installed",
			Details:   "Nomad is not installed on this system",
		}
		report.NomadChecks = append(report.NomadChecks, alert)
		return
	}

	checks := []struct {
		name  string
		cmd   string
		pass  func(string) bool
		issue string
		level string
	}{
		{
			name:  "Nomad TLS enabled",
			cmd:   "grep -i 'tls.*true' /etc/nomad.d/nomad.hcl 2>/dev/null",
			pass:  func(s string) bool { return len(s) > 0 },
			issue: "Nomad TLS encryption is not enabled",
			level: "WARNING",
		},
		{
			name:  "Nomad ACL enabled",
			cmd:   "grep -i 'acl.*enabled' /etc/nomad.d/nomad.hcl 2>/dev/null",
			pass:  func(s string) bool { return len(s) > 0 },
			issue: "Nomad ACL is not enabled",
			level: "WARNING",
		},
		{
			name:  "Nomad audit logging",
			cmd:   "grep -i 'audit' /etc/nomad.d/nomad.hcl 2>/dev/null",
			pass:  func(s string) bool { return len(s) > 0 },
			issue: "Nomad audit logging is not configured",
			level: "INFO",
		},
	}

	for _, check := range checks {
		out, _ := client.Run(check.cmd)
		if check.pass(out) {
			report.PassedCount++
		} else {
			alert := SecurityAlert{
				Level:     check.level,
				Component: "NOMAD",
				Issue:     check.name,
				Details:   check.issue,
			}
			if check.level == "CRITICAL" {
				report.CriticalCount++
			} else {
				report.WarningCount++
			}
			report.NomadChecks = append(report.NomadChecks, alert)
		}
	}
}

func sendAuditReport(cfg *TelegramConfig, report *AuditReport) error {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram config incomplete")
	}

	message := buildAuditMessage(report)
	return SendTelegramMessage(cfg.BotToken, cfg.ChatID, message)
}

func buildAuditMessage(report *AuditReport) string {
	emoji := map[string]string{
		"CRITICAL": "🔴",
		"WARNING":  "🟡",
		"INFO":     "ℹ️",
		"PASSED":   "✅",
	}

	message := fmt.Sprintf("*🔍 Security Audit Report*\n")
	message += fmt.Sprintf("Host: `%s`\n", report.Hostname)
	message += fmt.Sprintf("\n*Summary:*\n")
	message += fmt.Sprintf("%s Critical: %d\n", emoji["CRITICAL"], report.CriticalCount)
	message += fmt.Sprintf("%s Warnings: %d\n", emoji["WARNING"], report.WarningCount)
	message += fmt.Sprintf("%s Passed: %d\n", emoji["PASSED"], report.PassedCount)

	if report.CriticalCount > 0 {
		message += fmt.Sprintf("\n*🔴 CRITICAL ISSUES:*\n")
		for _, alert := range report.SystemChecks {
			if alert.Level == "CRITICAL" {
				message += fmt.Sprintf("• `%s`: %s\n", alert.Issue, alert.Details)
			}
		}
		for _, alert := range report.DockerChecks {
			if alert.Level == "CRITICAL" {
				message += fmt.Sprintf("• `%s`: %s\n", alert.Issue, alert.Details)
			}
		}
		for _, alert := range report.NomadChecks {
			if alert.Level == "CRITICAL" {
				message += fmt.Sprintf("• `%s`: %s\n", alert.Issue, alert.Details)
			}
		}
	}

	if report.WarningCount > 0 {
		message += fmt.Sprintf("\n*🟡 WARNINGS:*\n")
		for _, alert := range report.SystemChecks {
			if alert.Level == "WARNING" {
				message += fmt.Sprintf("• `%s`: %s\n", alert.Issue, alert.Details)
			}
		}
		for _, alert := range report.DockerChecks {
			if alert.Level == "WARNING" {
				message += fmt.Sprintf("• `%s`: %s\n", alert.Issue, alert.Details)
			}
		}
		for _, alert := range report.NomadChecks {
			if alert.Level == "WARNING" {
				message += fmt.Sprintf("• `%s`: %s\n", alert.Issue, alert.Details)
			}
		}
	}

	return message
}
