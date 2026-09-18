from app.detection.confidence import calculate_confidence


def test_default_confidence():
    result = calculate_confidence({
        "type": "account",
        "path": "_apt",
    })

    assert result["confidence_score"] == 50
    assert result["confidence"] == "LOW"


def test_authorized_keys_confidence():
    result = calculate_confidence({
        "type": "file",
        "path": "/home/test/.ssh/authorized_keys",
    })

    assert result["confidence_score"] == 70
    assert result["confidence"] == "MEDIUM"


def test_temp_hidden_path_confidence():
    result = calculate_confidence({
        "type": "file",
        "path": "/tmp/.suspicious.sh",
    })

    assert result["confidence_score"] == 75
    assert result["confidence"] == "MEDIUM"
