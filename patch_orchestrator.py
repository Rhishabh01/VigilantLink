
import re

with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "r", encoding="utf-8") as f:
    content = f.read()

# Add import
content = content.replace("from .scanner import run_heuristics, run_external_scans, check_google_safe_browsing", "from .scanner import run_heuristics, run_external_scans, check_google_safe_browsing\nfrom .rdap_client import fetch_domain_age_rdap")

# Add _safe_rdap function inside run_phase1
safe_gsb_pattern = r"(\s*async def _safe_gsb.*?return \[\], True)"
safe_rdap_code = """

    async def _safe_rdap(target_domain: str):
        try:
            logger.info(f\"[PHASE1-RDAP] Starting RDAP for {target_domain}\")
            return await asyncio.wait_for(fetch_domain_age_rdap(target_domain), timeout=2.0)
        except Exception as e:
            logger.warning(f\"[PHASE1-RDAP] Failed or timed out: {e}\")
            return None"""

content = re.sub(safe_gsb_pattern, r"\1" + safe_rdap_code, content, flags=re.DOTALL)

# Add rdap_task to tg2
tg2_pattern = r"gsb_task = tg2\.create_task\(_safe_gsb\(hop_urls\)\)"
content = content.replace(tg2_pattern, "gsb_task = tg2.create_task(_safe_gsb(hop_urls))\n        rdap_task = tg2.create_task(_safe_rdap(final_domain))")

# Get rdap_task result
gsb_result_pattern = r"gsb_threats, gsb_timed_out = gsb_task\.result\(\)\s*logger\.info\(f\"\[PHASE1\] GSB after redirect"
content = re.sub(gsb_result_pattern, "domain_age = rdap_task.result()\n    gsb_threats, gsb_timed_out = gsb_task.result()\n    logger.info(f\"[PHASE1] GSB after redirect", content)

# Add da to security dict
sec_dict_pattern = r"\"gsb_timed_out\": gsb_timed_out,"
content = content.replace(sec_dict_pattern, "\"gsb_timed_out\": gsb_timed_out,\n            \"da\": domain_age,")

with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success orchestrator")

