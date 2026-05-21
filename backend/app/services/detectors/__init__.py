from app.services.scanner import run_heuristics
from app.services.orchestrator import compute_final_score

class DetectorRegistry:
    def __init__(self):
        pass

    def run_all(self, data: dict) -> dict:
        final_url = data.get('final_url', '')
        hops = data.get('hops', [])
        metadata = data.get('metadata', {})
        dns_resolves = data.get('dns_resolves', True)
        ssl_error = data.get('ssl_error', False)
        
        # 1. Run local heuristics
        heuristics = run_heuristics(final_url)
        
        # 2. Map test input fields to the Phase 2 external scans schema
        external = {
            "ssl_cert_age_days": data.get("ssl_cert_age_days"),
            "domain_age_days": data.get("domain_age_days"),
            "phishtank_flagged": data.get("phishtank_flagged", False),
            "openphish_flagged": data.get("openphish_flagged", False),
            "gsb_threats": data.get("gsb_threats", []),
            "gsb_threat_type": data.get("gsb_threat_type"),
        }
        
        # 3. Compute score using the current scoring logic
        score, verdict, is_safe, reasons = compute_final_score(
            heuristics, external, hops, final_url, dns_resolves, bool(metadata), metadata, ssl_error
        )
        
        # 4. Return backward-compatible result structure expected by the tests
        return {
            'verdict': verdict,
            'risk_score': score,
            'is_safe': is_safe,
            'reasons': reasons,
            'contexts': [],
            'has_active_contexts': False,
            'trust': {
                'trust_score': 0,
                'trust_confidence': 0.0,
                'providers': []
            },
            'flags_triggered': [],
            'suppressed_flags': [],
            'context': {
                'effective_risk': score,
                'suppressed_flags': [],
                'unsuppressed_flags': []
            }
        }
