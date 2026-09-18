from app.investigation.inspect import (
    flatten_findings,
    investigate_finding,
)


def test_flatten_findings_assigns_ids():
    findings = {
        "users": [
            {"type": "account", "path": "_apt"},
        ],
        "ssh": [
            {"type": "authorized_keys", "path": "/home/test/.ssh/authorized_keys"},
        ],
    }

    result = flatten_findings(findings)

    assert len(result) == 2
    assert result[0]["finding_id"] == 1
    assert result[1]["finding_id"] == 2
    assert result[0]["category"] == "users"
    assert result[1]["category"] == "ssh"


def test_investigate_finding_returns_details():
    finding = {
        "finding_id": 1,
        "category": "ssh",
        "type": "authorized_keys",
        "path": "/home/test/.ssh/authorized_keys",
        "severity": "MEDIUM",
        "risk_score": 25,
        "confidence_score": 70,
        "evidence": {},
    }

    result = investigate_finding(finding)

    assert result["finding_id"] == 1
    assert result["category"] == "ssh"
    assert result["type"] == "authorized_keys"
    assert result["risk_score"] == 25
    assert result["confidence_score"] == 70
    assert "evidence" in result


def test_investigate_empty_evidence():
    finding = {
        "finding_id": 2,
        "category": "users",
        "type": "account",
        "path": "_apt",
    }

    result = investigate_finding(finding)

    assert result["finding_id"] == 2
    assert result["evidence"] == {}
    assert result["integrity"] is None
