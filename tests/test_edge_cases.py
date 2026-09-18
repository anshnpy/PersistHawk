from app.core.scanner import enrich_findings


def test_empty_findings():
    result = enrich_findings([])

    assert result == []


def test_account_missing_type_and_path():
    findings = [
        {
            "username": "_testuser",
        }
    ]

    result = enrich_findings(findings)

    assert len(result) == 1
    assert result[0]["type"] == "account"
    assert result[0]["path"] == "_testuser"


def test_file_evidence_error_is_handled():
    findings = [
        {
            "type": "file",
            "path": "/nonexistent/persist hawk-test-file",
        }
    ]

    result = enrich_findings(findings)

    assert len(result) == 1
    assert (
        "evidence" in result[0]
        or "evidence_error" in result[0]
    )
