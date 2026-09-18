from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path
import subprocess
import re

app = FastAPI(title="PersistHawk Web UI")

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (BASE_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/scan")
def scan():
    result = subprocess.run(
        ["python", "-m", "app.main", "--findings"],
        capture_output=True,
        text=True,
        cwd=PROJECT_DIR,
        timeout=120,
    )

    findings = []

    pattern = re.compile(
        r"\[(\d+)\]\s+(\w+)\s+\|\s+(\w+)\s+\|\s+risk=(\d+)\s+\|\s+(.*)"
    )

    for line in result.stdout.splitlines():
        match = pattern.search(line)

        if match:
            finding_id, severity, category, risk, path = match.groups()

            findings.append({
                "id": int(finding_id),
                "severity": severity,
                "category": category,
                "risk": int(risk),
                "path": path.strip(),
            })

    return {
        "success": result.returncode == 0,
        "findings": findings,
        "total": len(findings),
        "error": result.stderr,
    }


@app.get("/api/investigate/{finding_id}")
def investigate(finding_id: int):
    result = subprocess.run(
        [
            "python",
            "-m",
            "app.main",
            "--investigate-id",
            str(finding_id),
        ],
        capture_output=True,
        text=True,
        cwd=PROJECT_DIR,
        timeout=60,
    )

    output = result.stdout

    def extract(label):
        match = re.search(
            rf"^{re.escape(label)}:\s*(.*)$",
            output,
            re.MULTILINE,
        )
        return match.group(1).strip() if match else "N/A"

    risk_indicators = []

    marker = "Risk Indicators:"
    if marker in output:
        section = output.split(marker, 1)[1]

        if "Evidence Details:" in section:
            section = section.split("Evidence Details:", 1)[0]

        for line in section.splitlines():
            line = line.strip("- ").strip()
            if line and line != "No specific risk indicators detected.":
                risk_indicators.append(line)

    return {
        "success": result.returncode == 0,
        "finding_id": finding_id,
        "category": extract("Category"),
        "type": extract("Type"),
        "path": extract("Path"),
        "severity": extract("Severity"),
        "risk": extract("Risk"),
        "confidence": extract("Confidence"),
        "integrity": extract("Integrity"),
        "risk_indicators": risk_indicators,
        "raw": output,
        "error": result.stderr,
    }
