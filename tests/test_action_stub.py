"""Tests for GitHub Action configuration (Sprint A5)."""

from pathlib import Path

import pytest
import yaml


def test_github_action_exists():
    """Test that GitHub Action action.yml exists."""
    action_file = Path(__file__).parent.parent / "contrib" / "github-action" / "action.yml"
    assert action_file.exists(), "action.yml should exist in contrib/github-action/"


def test_github_action_valid_yaml():
    """Test that action.yml has valid YAML syntax."""
    action_file = Path(__file__).parent.parent / "contrib" / "github-action" / "action.yml"

    with open(action_file) as f:
        data = yaml.safe_load(f)

    assert isinstance(data, dict), "Action YAML should be a dictionary"


def test_github_action_required_fields():
    """Test that action.yml contains all required fields."""
    action_file = Path(__file__).parent.parent / "contrib" / "github-action" / "action.yml"

    with open(action_file) as f:
        action = yaml.safe_load(f)

    # Required top-level fields
    assert "name" in action, "Action must have a name"
    assert "description" in action, "Action must have a description"
    assert "runs" in action, "Action must specify runs configuration"

    # Required runs fields for composite action
    runs = action["runs"]
    assert "using" in runs, "Runs must specify 'using' field"
    assert runs["using"] == "composite", "Should be a composite action"
    assert "steps" in runs, "Composite action must have steps"
    assert len(runs["steps"]) > 0, "Must have at least one step"


def test_github_action_inputs():
    """Test that action has appropriate inputs."""
    action_file = Path(__file__).parent.parent / "contrib" / "github-action" / "action.yml"

    with open(action_file) as f:
        action = yaml.safe_load(f)

    if "inputs" in action:
        inputs = action["inputs"]

        # Should have target input
        if "target" in inputs:
            target = inputs["target"]
            assert "description" in target, "Target input should have description"
            assert "default" in target, "Target input should have default value"


def test_github_action_steps_structure():
    """Test that action steps are well-formed."""
    action_file = Path(__file__).parent.parent / "contrib" / "github-action" / "action.yml"

    with open(action_file) as f:
        action = yaml.safe_load(f)

    steps = action["runs"]["steps"]

    for i, step in enumerate(steps):
        assert "name" in step, f"Step {i} must have a name"

        # Composite action steps must specify shell
        if "run" in step:
            assert "shell" in step, f"Step {i} with 'run' must specify shell"


def test_github_action_sarif_upload_path():
    """Test that SARIF upload step uses correct file path."""
    action_file = Path(__file__).parent.parent / "contrib" / "github-action" / "action.yml"

    with open(action_file) as f:
        action = yaml.safe_load(f)

    steps = action["runs"]["steps"]

    # Find SARIF upload step
    sarif_upload_step = None
    for step in steps:
        if "uses" in step and "codeql-action/upload-sarif" in step["uses"]:
            sarif_upload_step = step
            break

    if sarif_upload_step:
        # Verify sarif_file path matches the scan output
        assert "with" in sarif_upload_step, "Upload step should have 'with' parameters"
        assert "sarif_file" in sarif_upload_step["with"], "Should specify sarif_file"

        sarif_file = sarif_upload_step["with"]["sarif_file"]
        assert "reports/scan.sarif" in sarif_file, \
            "SARIF file path should match scan output location"


def test_github_action_runs_aegis_seal():
    """Test that action actually runs aegis-seal scan."""
    action_file = Path(__file__).parent.parent / "contrib" / "github-action" / "action.yml"

    with open(action_file) as f:
        action = yaml.safe_load(f)

    steps = action["runs"]["steps"]

    # Find step that runs aegis-seal
    found_scan_step = False
    for step in steps:
        if "run" in step:
            run_cmd = step["run"]
            if "aegis-seal" in run_cmd and "scan" in run_cmd:
                found_scan_step = True
                # Verify SARIF format is specified
                assert "--format sarif" in run_cmd or "--format all" in run_cmd, \
                    "Scan should output SARIF format"
                break

    assert found_scan_step, "Action should include a step that runs aegis-seal scan"


def test_example_workflow_exists():
    """Test that example workflow exists."""
    workflow_file = Path(__file__).parent.parent / ".github" / "workflows" / "aegis.yml"
    assert workflow_file.exists(), "Example workflow should exist at .github/workflows/aegis.yml"


def test_example_workflow_valid_yaml():
    """Test that example workflow has valid YAML syntax."""
    workflow_file = Path(__file__).parent.parent / ".github" / "workflows" / "aegis.yml"

    with open(workflow_file) as f:
        data = yaml.safe_load(f)

    assert isinstance(data, dict), "Workflow should be a dictionary"
    assert "name" in data, "Workflow must have a name"
    # Note: YAML parses "on:" as boolean True, so check for either
    assert "on" in data or True in data, "Workflow must specify triggers"
    assert "jobs" in data, "Workflow must have jobs"


def test_example_workflow_uses_action():
    """Test that example workflow uses the Aegis Seal action."""
    workflow_file = Path(__file__).parent.parent / ".github" / "workflows" / "aegis.yml"

    with open(workflow_file) as f:
        workflow = yaml.safe_load(f)

    jobs = workflow["jobs"]
    assert len(jobs) > 0, "Workflow should have at least one job"

    # Find job that uses Aegis Seal action
    found_action_usage = False
    for job_name, job in jobs.items():
        if "steps" in job:
            for step in job["steps"]:
                if "uses" in step:
                    uses = step["uses"]
                    if "aegis-seal" in uses or "./contrib/github-action" in uses:
                        found_action_usage = True
                        break

    assert found_action_usage, "Example workflow should use the Aegis Seal action"
