from app.detection.correlation import correlate_findings


def test_correlation_counts_severity_and_confidence():
    findings = {
        "users": [
            {
                "type": "account",
                "path": "_apt",
                "severity": "LOW",
                "confidence": "LOW",
                "risk_score": 0,
                "confidence_score": 50,
            }
        ],
        "ssh": [
            {
                "type": "authorized_keys",
                "path": "/home/test/.ssh/authorized_keys",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "risk_score": 25,
                "confidence_score": 70,
            }
        ],
    }

    result = correlate_findings(findings)

    assert result["total_findings"] == 2
    assert result["severity_counts"]["LOW"] == 1
    assert result["severity_counts"]["MEDIUM"] == 1
    assert len(result["correlated_findings"]) == 1


def test_empty_correlation():
    result = correlate_findings({})

    assert result["total_findings"] == 0
    assert result["correlated_findings"] == []
