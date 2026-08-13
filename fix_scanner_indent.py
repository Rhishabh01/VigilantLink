
import re

with open("d:/Project26/Extension/backend/app/services/scanner.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix dangling except
dangling_except = r"\s*except Exception as e:\s*logger\.debug\(f\"\[RDAP\] Lookup failed for \{root_domain\}: \{e\}\"\)\s*return None\n"
content = re.sub(dangling_except, "\n", content)

# Fix indentation of task_pt
content = content.replace("        task_pt = asyncio.create_task(_safe_phishtank())", "    task_pt = asyncio.create_task(_safe_phishtank())")

with open("d:/Project26/Extension/backend/app/services/scanner.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success fix scanner indent")

