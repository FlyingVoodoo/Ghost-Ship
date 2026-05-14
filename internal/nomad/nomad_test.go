package nomad

import (
	"testing"

	"github.com/matvejefimovyh/ghost-ship/internal/mocks"
)

func TestExtractNomadState_Simple(t *testing.T) {
	// nomad job list -json should return array with ID
	list := `[{"ID":"job1"}]`
	inspect := `{"ID":"job1","Name":"job1","Type":"service","Datacenters":["dc1"],"Status":"running","TaskGroups":[]}`

	mock := mocks.NewMockSSHRunner(map[string]string{
		"which nomad":          "/usr/bin/nomad\n",
		"nomad version":        "Nomad v1.0.0\n",
		"docker --version":     "Docker version 20.10",
		"nomad job list -json": list,
		"nomad job inspect":    inspect,
	})

	st, err := ExtractNomadState(mock)
	if err != nil {
		t.Fatalf("ExtractNomadState error: %v", err)
	}
	if len(st.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(st.Jobs))
	}
	if st.Jobs[0].ID != "job1" {
		t.Fatalf("unexpected job id: %s", st.Jobs[0].ID)
	}
}

func TestRestoreNomadState_WriteAndRun(t *testing.T) {
	job := NomadJob{ID: "job1", RawJobspec: "{\"ID\":\"job1\"}"}
	state := &NomadState{Jobs: []NomadJob{job}}

	mock := mocks.NewMockSSHRunner(map[string]string{
		"cat > /tmp/job1.nomad.json":         "",
		"nomad job run /tmp/job1.nomad.json": "OK",
	})

	if err := RestoreNomadState(mock, state); err != nil {
		t.Fatalf("RestoreNomadState error: %v", err)
	}
}
