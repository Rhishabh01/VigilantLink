
import re

with open("d:/Project26/Extension/backend/app/services/scanner.py", "r", encoding="utf-8") as f:
    content = f.read()

# Remove fetch_domain_age_rdap import
content = content.replace("from .rdap_client import fetch_domain_age_rdap, extract_root_domain", "from .rdap_client import extract_root_domain")

# Remove _safe_rdap function
rdap_func = r"\s*async def _safe_rdap\(\) -> Optional\[int\]:.*?return None\n"
content = re.sub(rdap_func, "\n", content, flags=re.DOTALL)

# Remove task_rdap
content = content.replace("task_rdap = asyncio.create_task(_safe_rdap())\n", "")
content = content.replace("task_rdap, ", "")

# Remove rdap cancellation
rdap_cancel = r"\s*elif task == task_rdap:\s*rdap_timed_out = True"
content = re.sub(rdap_cancel, "", content)

# Remove domain_age extraction
rdap_result = r"\s*domain_age = task_rdap\.result.*?else None"
content = re.sub(rdap_result, "", content)

# In threat_type determination, remove domain_age check
threat_age = r"\s*elif domain_age is not None and domain_age < NEWLY_REGISTERED_DAYS:\s*threat_type = \"Newly Registered Domain\""
content = re.sub(threat_age, "", content)

# Remove from return dict
rdap_ret = r"\s*\"domain_age_days\": domain_age,"
content = re.sub(rdap_ret, "", content)

rdap_timeout_ret = r"\s*\"rdap_timed_out\": rdap_timed_out,"
content = re.sub(rdap_timeout_ret, "", content)

with open("d:/Project26/Extension/backend/app/services/scanner.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success scanner fix")

