package examples_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type exampleManifest struct {
	SchemaVersion int           `json:"schemaVersion"`
	Repository    string        `json:"repository"`
	ProofSources  []proofSource `json:"proofSources"`
	Examples      []example     `json:"examples"`
}

type proofSource struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Path string `json:"path"`
}

type example struct {
	ID             string            `json:"id"`
	Ecosystem      string            `json:"ecosystem"`
	Owner          string            `json:"owner"`
	SourcePath     string            `json:"sourcePath"`
	Availability   string            `json:"availability"`
	Versions       map[string]string `json:"versions"`
	OfflineCommand string            `json:"offlineCommand"`
	Assertion      string            `json:"assertion"`
	WorkflowPath   string            `json:"workflowPath"`
	JobID          string            `json:"jobId"`
	Cleanup        string            `json:"cleanup"`
	LiveGate       any               `json:"liveGate"`
	ProofIDs       []string          `json:"proofIds"`
}

func TestRunnableExamples(t *testing.T) {
	tests := []struct {
		name    string
		command []string
		want    string
	}{
		{
			name:    "secret safety",
			command: []string{"go", "run", "../examples/secret-safety"},
			want:    "formatted=[REDACTED]\nvalid=true\nexplicit-bytes=13\ncopy-isolated=true\n",
		},
		{
			name:    "references",
			command: []string{"go", "run", "../examples/references"},
			want:    "canonical=local://service/production/token\nscheme=local\npath=service/production/token\ncontained=true\n",
		},
		{
			name:    "local store lifecycle",
			command: []string{"go", "run", "../examples/local-store"},
			want:    "created=true\nresolved=true\nupdated=true\nlisted=1\ndeleted=deleted\nabsent=absent\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(test.command[0], test.command[1:]...)
			command.Env = append(os.Environ(), "GOWORK=off")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%s failed: %v\n%s", strings.Join(test.command, " "), err, output)
			}
			if got := string(output); got != test.want {
				t.Fatalf("output = %q, want %q", got, test.want)
			}
		})
	}
}

func TestContractTestExample(t *testing.T) {
	command := exec.Command("go", "test", "../examples/contracttest", "-run", "^TestLocalStoreContract$", "-count=1")
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("contract test example failed: %v\n%s", err, output)
	}
	if got := string(output); !strings.Contains(got, "ok  \tgithub.com/looprig/secrets/examples/contracttest") {
		t.Fatalf("output = %q, want package success", got)
	}
}

func TestExampleManifestAndWorkflow(t *testing.T) {
	repositoryRoot := filepath.Clean("..")
	manifestBytes, err := os.ReadFile(filepath.Join(repositoryRoot, "testdata/docs/examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest exampleManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 1 || manifest.Repository != "secrets" {
		t.Fatalf("manifest identity = (%d, %q)", manifest.SchemaVersion, manifest.Repository)
	}
	if len(manifest.Examples) != 4 {
		t.Fatalf("manifest has %d examples, want 4", len(manifest.Examples))
	}

	proofs := make(map[string]proofSource, len(manifest.ProofSources))
	for _, proof := range manifest.ProofSources {
		if proof.ID == "" || proof.Type == "" || proof.Path == "" {
			t.Fatalf("incomplete proof source: %#v", proof)
		}
		if _, err := os.Stat(filepath.Join(repositoryRoot, proof.Path)); err != nil {
			t.Fatalf("proof source %q: %v", proof.ID, err)
		}
		if _, duplicate := proofs[proof.ID]; duplicate {
			t.Fatalf("duplicate proof source id %q", proof.ID)
		}
		proofs[proof.ID] = proof
	}

	workflowBytes, err := os.ReadFile(filepath.Join(repositoryRoot, ".github/workflows/docs-examples.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(workflowBytes)
	if !strings.Contains(workflow, "docs-examples:") || !strings.Contains(workflow, "GOWORK=off go test -race ./...") {
		t.Fatal("workflow is missing the docs-examples job or race suite")
	}

	exampleIDs := make(map[string]struct{}, len(manifest.Examples))
	for _, example := range manifest.Examples {
		if !strings.HasPrefix(example.ID, "example-secrets-") {
			t.Errorf("example id %q is not globally namespaced", example.ID)
		}
		if _, duplicate := exampleIDs[example.ID]; duplicate {
			t.Errorf("duplicate example id %q", example.ID)
		}
		if _, collides := proofs[example.ID]; collides {
			t.Errorf("example id %q collides with a proof source", example.ID)
		}
		exampleIDs[example.ID] = struct{}{}
		if example.Ecosystem != "go" || example.Owner != "secrets" || example.Availability != "source-workspace" {
			t.Errorf("example %q identity fields are invalid", example.ID)
		}
		if got := example.Versions["github.com/looprig/secrets"]; len(example.Versions) != 1 || got != "source-workspace" {
			t.Errorf("example %q versions = %#v", example.ID, example.Versions)
		}
		if example.SourcePath == "" || example.OfflineCommand == "" || example.Assertion == "" || example.Cleanup == "" {
			t.Errorf("example %q has an empty required field", example.ID)
		}
		if example.WorkflowPath != ".github/workflows/docs-examples.yml" || example.JobID != "docs-examples" || example.LiveGate != nil {
			t.Errorf("example %q automation fields are invalid", example.ID)
		}
		if _, err := os.Stat(filepath.Join(repositoryRoot, example.SourcePath)); err != nil {
			t.Errorf("example %q source: %v", example.ID, err)
		}
		if !strings.Contains(workflow, example.OfflineCommand) {
			t.Errorf("workflow does not contain command %q", example.OfflineCommand)
		}
		if len(example.ProofIDs) == 0 {
			t.Errorf("example %q has no proof IDs", example.ID)
		}
		for _, proofID := range example.ProofIDs {
			if _, ok := proofs[proofID]; !ok {
				t.Errorf("example %q references missing proof %q", example.ID, proofID)
			}
		}
	}
}
