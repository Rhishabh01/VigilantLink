
with open("d:/Project26/Extension/backend/app/main.py", "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace(
    "\"ts\": sec[\"typosquatting_detected\"],",
    "\"ts\": sec[\"typosquatting_detected\"],\n                \"da\": sec.get(\"da\"),"
)

with open("d:/Project26/Extension/backend/app/main.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Success stage1 response fix")

