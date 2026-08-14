
with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace("domain_age = rdap_task.result()\n    domain_age = rdap_task.result()", "domain_age = rdap_task.result()")

with open("d:/Project26/Extension/backend/app/services/orchestrator.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success deduplicate")

