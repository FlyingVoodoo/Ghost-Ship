package mocks

// Simple hand-written mock for sshutil.SSHRunner used in unit tests when
// mockgen is not available. It matches the minimal `Run(cmd string) (string, error)`
// and `Close() error` contract.

import (
	"errors"
	"strings"
)

type MockSSHRunner struct {
	Responses map[string]string
	Commands  []string
}

func NewMockSSHRunner(responses map[string]string) *MockSSHRunner {
	if responses == nil {
		responses = make(map[string]string)
	}
	return &MockSSHRunner{Responses: responses}
}

func (m *MockSSHRunner) Run(cmd string) (string, error) {
	m.Commands = append(m.Commands, cmd)
	for k, v := range m.Responses {
		if strings.Contains(cmd, k) {
			return v, nil
		}
	}
	return "", errors.New("not found")
}

func (m *MockSSHRunner) Close() error { return nil }
