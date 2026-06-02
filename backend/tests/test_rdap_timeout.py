import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.orchestrator import compute_final_score, VERDICT_YELLOW_THRESHOLD

def test_rdap_timeout_penalty():
    # Base heuristic results (simulated)
    heuristics = {
        "typosquatting_detected": False,
        "punycode_detected": False,
        "synergy_detected": False,
        "has_suspicious_keywords": True,
    }
    
    # Let's create an external result where only RDAP timed out
    # Also set some condition to trigger uncertainty (e.g. near threshold)
    # The new penalty applies if base_score >= VERDICT_YELLOW_THRESHOLD - 5 (30)
    
    # We will simulate a score of 30 from something else (e.g. SSL error = 30)
    
    external_rdap_ok = {
        "rdap_timed_out": False,
        "ssl_timed_out": False,
        "phishtank_timed_out": False,
        "openphish_timed_out": False,
        "domain_age_days": 1000,
        "ssl_cert_age_days": 1000,
    }
    
    external_rdap_timed_out = {
        "rdap_timed_out": True,
        "ssl_timed_out": False,
        "phishtank_timed_out": False,
        "openphish_timed_out": False,
        "domain_age_days": 1000,
        "ssl_cert_age_days": 1000,
    }
    
    hops = [{"url": "https://example.com", "status_code": 200}]
    
    score_ok, verdict_ok, _, reasons_ok = compute_final_score(
        heuristics=heuristics,
        external=external_rdap_ok,
        hops=hops,
        final_url="https://example.com",
        dns_resolves=True,
        has_metadata=True,
        ssl_error=True, # gives +30
    )
    
    score_timeout, verdict_timeout, _, reasons_timeout = compute_final_score(
        heuristics=heuristics,
        external=external_rdap_timed_out,
        hops=hops,
        final_url="https://example.com",
        dns_resolves=True,
        has_metadata=True,
        ssl_error=True, # gives +30
    )
    
    # score_ok should be 30
    # score_timeout should be 30 + 5 (uncertainty penalty) = 35
    assert score_ok == 30
    assert score_timeout == 35
    
    # reason should include uncertainty penalty
    assert any("Uncertainty penalty" in r for r in reasons_timeout)
    assert not any("Uncertainty penalty" in r for r in reasons_ok)

def test_rdap_timeout_no_penalty_for_safe_links():
    # Base heuristic results (simulated)
    heuristics = {
        "typosquatting_detected": False,
        "punycode_detected": False,
        "synergy_detected": False,
        "has_suspicious_keywords": False,
    }
    
    # Safe link, no other issues (base score 0)
    external_rdap_timed_out = {
        "rdap_timed_out": True,
        "ssl_timed_out": False,
        "phishtank_timed_out": False,
        "openphish_timed_out": False,
        "domain_age_days": 1000,
        "ssl_cert_age_days": 1000,
    }
    
    hops = [{"url": "https://example.com", "status_code": 200}]
    
    score_timeout, verdict_timeout, _, reasons_timeout = compute_final_score(
        heuristics=heuristics,
        external=external_rdap_timed_out,
        hops=hops,
        final_url="https://example.com",
        dns_resolves=True,
        has_metadata=True,
        ssl_error=False,
    )
    
    # The penalty should NOT be applied for only 1 timeout on a safe link
    # (requires timeout_count >= 2 OR is_suspicious OR near threshold)
    assert score_timeout == 0
