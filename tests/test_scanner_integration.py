from app.core.scanner import enrich_findings


def test_scanner_enriches_findings():
    findings = [
        {
            "type": "file",
            "path": "/tmp/.suspicious.sh",
        }
    ]

    result = enrich_findings(findings)

    assert len(result) == 1
    assert result[0]["type"] == "file"
    assert result[0]["path"] == "/tmp/.suspicious.sh"

    # Risk and confidence enrichment
    assert result[0]["risk_score"] == 30
    assert result[0]["severity"] == "MEDIUM"
    assert result[0]["confidence_score"] == 75
    assert result[0]["confidence"] == "MEDIUM"

    # Evidence should be present or report an error
    assert (
        "evidence" in result[0]
        or "evidence_error" in result[0]
    )
