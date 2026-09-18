from app.detection.risk import calculate_risk_score


def test_temp_path_risk():
    finding = {
        "type": "file",
        "path": "/tmp/suspicious_startup.sh",
    }

    result = calculate_risk_score(finding)

    assert result["risk_score"] == 25
    assert result["severity"] == "MEDIUM"
    assert "Temporary directory path detected." in result["risk_reasons"]
