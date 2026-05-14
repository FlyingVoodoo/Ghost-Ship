package nomad

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

type NomadJob struct {
	ID          string                   `json:"ID"`
	Name        string                   `json:"Name"`
	Type        string                   `json:"Type"`
	Datacenters []string                 `json:"Datacenters"`
	Status      string                   `json:"Status"`
	TaskGroups  []map[string]interface{} `json:"TaskGroups"`
	Meta        map[string]string        `json:"Meta"`
	RawJobspec  string                   `json:"raw_jobspec"`
}

type NomadState struct {
	Jobs        []NomadJob             `json:"jobs"`
	Nodes       []string               `json:"nodes"`
	Allocations map[string]interface{} `json:"allocations"`
}

func ExtractNomadState(client sshutil.SSHRunner) (*NomadState, error) {
	slog.Info("extracting nomad state")

	if err := ValidateNomadInstall(client); err != nil {
		slog.Warn("nomad not available", "error", err)
		return &NomadState{
			Jobs:        []NomadJob{},
			Allocations: make(map[string]interface{}),
		}, nil
	}

	state := &NomadState{
		Allocations: make(map[string]interface{}),
	}

	jobs, err := extractNomadJobs(client)
	if err != nil {
		slog.Warn("failed to extract nomad jobs", "error", err)
	} else {
		state.Jobs = jobs
	}

	slog.Info("nomad state extracted", "jobs", len(state.Jobs))
	return state, nil
}

func extractNomadJobs(client sshutil.SSHRunner) ([]NomadJob, error) {
	out, err := client.Run("nomad job list -json 2>/dev/null")
	if err != nil {
		return nil, fmt.Errorf("nomad job list failed: %w", err)
	}

	var jobList []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &jobList); err != nil {
		return nil, fmt.Errorf("failed to parse job list: %w", err)
	}

	var jobs []NomadJob
	for _, jobInfo := range jobList {
		if jobID, ok := jobInfo["ID"].(string); ok {
			job, err := extractNomadJobDetails(client, jobID)
			if err != nil {
				slog.Debug("failed to extract job details", "id", jobID)
				continue
			}
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

func extractNomadJobDetails(client sshutil.SSHRunner, jobID string) (NomadJob, error) {
	out, err := client.Run(fmt.Sprintf("nomad job inspect %s -json 2>/dev/null", jobID))
	if err != nil {
		return NomadJob{}, err
	}

	var jobData map[string]interface{}
	if err := json.Unmarshal([]byte(out), &jobData); err != nil {
		return NomadJob{}, err
	}

	job := NomadJob{
		Meta:       make(map[string]string),
		RawJobspec: out,
	}

	if id, ok := jobData["ID"].(string); ok {
		job.ID = id
	}
	if name, ok := jobData["Name"].(string); ok {
		job.Name = name
	}
	if jobType, ok := jobData["Type"].(string); ok {
		job.Type = jobType
	}
	if status, ok := jobData["Status"].(string); ok {
		job.Status = status
	}

	if datacenters, ok := jobData["Datacenters"].([]interface{}); ok {
		for _, dc := range datacenters {
			if s, ok := dc.(string); ok {
				job.Datacenters = append(job.Datacenters, s)
			}
		}
	}

	if meta, ok := jobData["Meta"].(map[string]interface{}); ok {
		for k, v := range meta {
			if s, ok := v.(string); ok {
				job.Meta[k] = s
			}
		}
	}

	if taskGroups, ok := jobData["TaskGroups"].([]interface{}); ok {
		for _, tg := range taskGroups {
			if m, ok := tg.(map[string]interface{}); ok {
				job.TaskGroups = append(job.TaskGroups, m)
			}
		}
	}

	return job, nil
}

func RestoreNomadState(client sshutil.SSHRunner, state *NomadState) error {
	if len(state.Jobs) == 0 {
		slog.Info("no nomad jobs to restore")
		return nil
	}

	slog.Info("restoring nomad jobs", "count", len(state.Jobs))

	for _, job := range state.Jobs {
		if err := restoreNomadJob(client, job); err != nil {
			slog.Warn("failed to restore job", "id", job.ID, "error", err)
			continue
		}
		slog.Info("job restored", "id", job.ID)
	}

	return nil
}

func restoreNomadJob(client sshutil.SSHRunner, job NomadJob) error {
	if job.RawJobspec == "" {
		return fmt.Errorf("no job specification available")
	}

	jobFile := fmt.Sprintf("/tmp/%s.nomad.json", job.ID)
	writeCmd := fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF", jobFile, job.RawJobspec)

	_, err := client.Run(writeCmd)
	if err != nil {
		return fmt.Errorf("failed to write job spec: %w", err)
	}

	runCmd := fmt.Sprintf("nomad job run %s 2>&1", jobFile)
	out, err := client.Run(runCmd)
	if err != nil {
		return fmt.Errorf("nomad job run failed: %s - %w", out, err)
	}

	client.Run(fmt.Sprintf("rm -f %s", jobFile))

	return nil
}

func ValidateNomadInstall(client sshutil.SSHRunner) error {
	_, err := client.Run("which nomad")
	if err != nil {
		return fmt.Errorf("nomad not installed")
	}

	_, err = client.Run("nomad version")
	if err != nil {
		return fmt.Errorf("nomad not responding")
	}

	hasDocker, _ := client.Run("docker --version")
	hasContainerd, _ := client.Run("which containerd")

	if hasDocker == "" && hasContainerd == "" {
		return fmt.Errorf("neither docker nor containerd found - nomad requires a container runtime")
	}

	return nil
}

func GetNomadAllocations(client sshutil.SSHRunner, jobID string) (map[string]interface{}, error) {
	out, err := client.Run(fmt.Sprintf("nomad job allocations %s -json 2>/dev/null", jobID))
	if err != nil {
		return nil, fmt.Errorf("failed to get allocations: %w", err)
	}

	var allocations map[string]interface{}
	if err := json.Unmarshal([]byte(out), &allocations); err != nil {
		return nil, err
	}

	return allocations, nil
}
