
import re

with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix tg2
content = content.replace(
    "gsb_task = tg2.create_task(_safe_gsb(hop_urls))",
    "gsb_task = tg2.create_task(_safe_gsb(hop_urls))\n        rdap_task = tg2.create_task(_safe_rdap(final_domain))"
)

# Get rdap_task result
gsb_result_pattern = r"gsb_threats, gsb_timed_out = gsb_task\.result\(\)\s*logger\.info\(f\"\[PHASE1\] GSB after redirect"
content = re.sub(gsb_result_pattern, "domain_age = rdap_task.result()\n    gsb_threats, gsb_timed_out = gsb_task.result()\n    logger.info(f\"[PHASE1] GSB after redirect", content)

# Add da to security dict
sec_dict_pattern = r"\"gsb_timed_out\": gsb_timed_out,"
content = content.replace(
    "\"gsb_timed_out\": gsb_timed_out,",
    "\"gsb_timed_out\": gsb_timed_out,\n            \"da\": domain_age,"
)

with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success fix")

