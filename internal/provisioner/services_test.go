package provisioner

import (
	"strings"
	"testing"

	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/internal/mocks"
)

func TestDeployServices_OneService(t *testing.T) {
	mock := mocks.NewMockSSHRunner(map[string]string{
		"mkdir -p /opt/ghost-ship/services":                   "",
		"test -f /opt/ghost-ship/services/docker-compose.yml": "",
		"cat > /opt/ghost-ship/services/docker-compose.yml":   "",
		"docker compose up -d --pull always --remove-orphans": "service-up",
	})

	service := config.ServiceSpec{
		Name:    "x-ui",
		Image:   "ghcr.io/mhsanaei/3x-ui:latest",
		Volumes: []string{"/opt/3x-ui/db:/etc/x-ui"},
		Env: map[string]string{
			"PUID": "1000",
		},
		Ports:    []config.PortMapping{{Host: 54321, Container: 54321, Protocol: "tcp"}},
		Count:    1,
		MemoryMB: 256,
	}

	if err := DeployServices(mock, []config.ServiceSpec{service}); err != nil {
		t.Fatalf("DeployServices returned error: %v", err)
	}
}

func TestDeployServices_IdempotentComposeWrite(t *testing.T) {
	service := config.ServiceSpec{
		Name:  "x-ui",
		Image: "ghcr.io/mhsanaei/3x-ui:latest",
		Env: map[string]string{
			"PUID": "1000",
		},
		Volumes: []string{"/opt/3x-ui/db:/etc/x-ui"},
		Ports:   []config.PortMapping{{Host: 54321, Container: 54321, Protocol: "tcp"}},
	}

	composeYAML, _, err := buildComposeProject([]config.ServiceSpec{service})
	if err != nil {
		t.Fatalf("buildComposeProject returned error: %v", err)
	}

	mock := mocks.NewMockSSHRunner(map[string]string{
		"mkdir -p /opt/ghost-ship/services":                   "",
		"test -f /opt/ghost-ship/services/docker-compose.yml": composeYAML,
		"docker compose up -d --pull always --remove-orphans": "service-up",
	})

	if err := DeployServices(mock, []config.ServiceSpec{service}); err != nil {
		t.Fatalf("DeployServices returned error: %v", err)
	}

	for _, cmd := range mock.Commands {
		if strings.Contains(cmd, "cat > /opt/ghost-ship/services/docker-compose.yml") {
			t.Fatalf("expected compose file write to be skipped, but saw command %q", cmd)
		}
	}
}

func TestBuildComposeProject_GeneratesCompose(t *testing.T) {
	composeYAML, scaleArgs, err := buildComposeProject([]config.ServiceSpec{{
		Name:  "x-ui",
		Image: "ghcr.io/mhsanaei/3x-ui:latest",
		Env: map[string]string{
			"PUID": "1000",
		},
		Volumes: []string{"/opt/3x-ui/db:/etc/x-ui"},
		Ports:   []config.PortMapping{{Host: 54321, Container: 54321, Protocol: "tcp"}},
	}})
	if err != nil {
		t.Fatalf("buildComposeProject returned error: %v", err)
	}
	if len(scaleArgs) != 0 {
		t.Fatalf("expected no scale args, got %v", scaleArgs)
	}
	if composeYAML == "" {
		t.Fatalf("expected compose yaml to be generated")
	}
	if got, want := composeYAML, "x-ui:"; !containsString(got, want) {
		t.Fatalf("compose yaml missing %q:\n%s", want, got)
	}
}

func TestBuildComposeProject_RejectsPortScaling(t *testing.T) {
	_, _, err := buildComposeProject([]config.ServiceSpec{{
		Name:  "x-ui",
		Image: "ghcr.io/mhsanaei/3x-ui:latest",
		Count: 2,
		Ports: []config.PortMapping{{Host: 54321, Container: 54321, Protocol: "tcp"}},
	}})
	if err == nil {
		t.Fatalf("expected error when scaling a service with ports")
	}
}

func TestDeployServices_ValidatesNameAndImage(t *testing.T) {
	if err := DeployServices(mocks.NewMockSSHRunner(nil), []config.ServiceSpec{{Image: "img"}}); err == nil {
		t.Fatalf("expected error when service name is missing")
	}
	if err := DeployServices(mocks.NewMockSSHRunner(nil), []config.ServiceSpec{{Name: "svc"}}); err == nil {
		t.Fatalf("expected error when service image is missing")
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (len(needle) == 0 || (len(haystack) > 0 && (stringIndex(haystack, needle) >= 0)))
}

func stringIndex(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
