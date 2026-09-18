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


def test_authorized_keys_risk():
    finding = {
        "type": "file",
        "path": "/home/test/.ssh/authorized_keys",
    }

    result = calculate_risk_score(finding)

    assert result["risk_score"] == 25
    assert result["severity"] == "MEDIUM"
    assert "SSH authorized keys location detected." in result["risk_reasons"]
    assert "Hidden configuration path detected." in result["risk_reasons"]


def test_hidden_path_risk():
    finding = {
        "type": "file",
        "path": "/home/test/.config/.hidden",
    }

    result = calculate_risk_score(finding)

    assert result["risk_score"] == 5
    assert result["severity"] == "LOW"
