import subprocess
import sys


def test_findings_command():
    result = subprocess.run(
        [sys.executable, "-m", "app.main", "--findings"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Finding Index:" in result.stdout


def test_investigate_id_command():
    result = subprocess.run(
        [sys.executable, "-m", "app.main", "--investigate-id", "1"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Investigation Results:" in result.stdout
    assert "Finding ID: 1" in result.stdout
