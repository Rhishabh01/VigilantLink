
with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "r", encoding="utf-8") as f:
    content = f.read()

# Replace domain_age = external.get("domain_age_days")
content = content.replace("domain_age = external.get(\"domain_age_days\")", "domain_age = phase1_result.get(\"security\", {}).get(\"da\")")

# Remove "domain_age_days": external.get("domain_age_days"),
content = content.replace("\"domain_age_days\": external.get(\"domain_age_days\"),", "")

# Update the "domain_age_days": None, fallback in the exception block
content = content.replace("\"domain_age_days\": None,", "")

with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success orchestrator phase2 fix")

